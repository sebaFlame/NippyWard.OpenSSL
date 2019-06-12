// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;

namespace OpenSSL.Core.SSL.Pipelines
{
    /// <summary>
    /// Default <see cref="PipeWriter"/> and <see cref="PipeReader"/> implementation.
    /// </summary>
    public abstract partial class Pipe
    {
        internal const int SegmentPoolSize = 16;

        private static readonly Action<object> s_signalReaderAwaitable = state => ((Pipe)state).ReaderCancellationRequested();
        private static readonly Action<object> s_signalWriterAwaitable = state => ((Pipe)state).WriterCancellationRequested();
        private static readonly Action<object> s_invokeCompletionCallbacks = state => ((PipeCompletionCallbacks)state).Execute();

        // These callbacks all point to the same methods but are different delegate types
        private static readonly ContextCallback s_executionContextCallback = ExecuteWithExecutionContext;
        private static readonly ContextCallback s_executionContextRawCallback = ExecuteWithoutExecutionContext;
        private static readonly SendOrPostCallback s_syncContextExecutionContextCallback = ExecuteWithExecutionContext;
        private static readonly SendOrPostCallback s_syncContextExecuteWithoutExecutionContextCallback = ExecuteWithoutExecutionContext;
        private static readonly Action<object> s_scheduleWithExecutionContextCallback = ExecuteWithExecutionContext;

        // This sync objects protects the following state:
        // 1. _commitHead & _commitHeadIndex
        // 2. _length
        // 3. _readerAwaitable & _writerAwaitable
        private readonly object _sync = new object();

        private readonly MemoryPool<byte> _pool;
        private readonly int _minimumSegmentSize;
        private readonly long _pauseWriterThreshold;
        private readonly long _resumeWriterThreshold;

        private readonly PipeScheduler _readerScheduler;
        private readonly PipeScheduler _writerScheduler;

        private readonly BufferSegment[] _bufferSegmentPool;

        private readonly DefaultPipeReader _reader;
        private readonly DefaultPipeWriter _writer;

        private int _pooledSegmentCount;

        private PipeCompletion _writerCompletion;
        private PipeCompletion _readerCompletion;

        private PipeReaderState _readingState;

        private bool _disposed;

        private PipeAwaitable _readerAwaitable;
        private PipeAwaitable _writerAwaitable;

        private BufferSequence _writerSequence;
        private BufferSequence _readerSequence;

        internal SocketConnection CurrentConnection;

        /// <summary>
        /// Initializes the <see cref="Pipe"/> using <see cref="PipeOptions.Default"/> as options.
        /// </summary>
        public Pipe() : this(PipeOptions.Default)
        {
        }

        /// <summary>
        /// Initializes the <see cref="Pipe"/> with the specified <see cref="PipeOptions"/>.
        /// </summary>
        public Pipe(PipeOptions options)
        {
            if (options == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.options);
            }

            _bufferSegmentPool = new BufferSegment[SegmentPoolSize];

            _readingState = default;
            _readerCompletion = default;
            _writerCompletion = default;

            _pool = options.Pool;
            _minimumSegmentSize = options.MinimumSegmentSize;
            _pauseWriterThreshold = options.PauseWriterThreshold;
            _resumeWriterThreshold = options.ResumeWriterThreshold;
            _readerScheduler = options.ReaderScheduler;
            _writerScheduler = options.WriterScheduler;

            var useSynchronizationContext = options.UseSynchronizationContext;
            this._readerAwaitable = new PipeAwaitable(completed: false, useSynchronizationContext);
            this._writerAwaitable = new PipeAwaitable(completed: true, useSynchronizationContext);

            _reader = new DefaultPipeReader(this);
            _writer = new DefaultPipeWriter(this);

            this._writerSequence = new BufferSequence();
            this._readerSequence = new BufferSequence();
        }

        internal Pipe(PipeOptions options, SocketConnection connection)
            : this(options)
        {
            this.CurrentConnection = connection;
        }

        private void ResetState()
        {
            _readerCompletion.Reset();
            _writerCompletion.Reset();

            this._writerSequence.Reset();
            this._readerSequence.Reset();
        }

        internal Memory<byte> GetMemory(int sizeHint)
        {
            return this.GetMemoryInternal(sizeHint, ref this._writerSequence);
        }

        internal abstract Memory<byte> GetMemoryInternal(int sizeHint, ref BufferSequence writerSequence);

        internal Memory<byte> GetMemoryInternal(int sizeHint)
        {
            return this.GetMemory(sizeHint, ref this._writerSequence);
        }

        internal Memory<byte> GetMemory(int sizeHint, ref BufferSequence bufferSequence)
        {
            if (_writerCompletion.IsCompleted)
            {
                ThrowHelper.ThrowInvalidOperationException_NoWritingAllowed();
            }

            if (sizeHint < 0)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(ExceptionArgument.minimumSize);
            }

            lock (_sync)
            {
                BufferSegment segment = bufferSequence.WritingHead ?? AllocateWriteHeadUnsynchronized(sizeHint, ref bufferSequence);

                int bytesLeftInBuffer = segment.WritableBytes;

                // If inadequate bytes left or if the segment is readonly
                if (bytesLeftInBuffer == 0 || bytesLeftInBuffer < sizeHint || segment.ReadOnly)
                {
                    BufferSegment nextSegment = CreateSegmentUnsynchronized();
                    nextSegment.SetMemory(_pool.Rent(GetSegmentSize(sizeHint)));

                    segment.SetNext(nextSegment);

                    bufferSequence.WritingHead = nextSegment;
                }
            }

            return bufferSequence.WritingHead.AvailableMemory.Slice(bufferSequence.WritingHead.End, bufferSequence.WritingHead.WritableBytes);
        }

        private BufferSegment AllocateWriteHeadUnsynchronized(int sizeHint, ref BufferSequence bufferSequence)
        {
            BufferSegment segment = null;

            if (bufferSequence.CommitHead != null && !bufferSequence.CommitHead.ReadOnly)
            {
                // Try to return the tail so the calling code can append to it
                int remaining = bufferSequence.CommitHead.WritableBytes;

                if (sizeHint <= remaining && remaining > 0)
                {
                    // Free tail space of the right amount, use that
                    segment = bufferSequence.CommitHead;
                }
            }

            if (segment == null)
            {
                // No free tail space, allocate a new segment
                segment = CreateSegmentUnsynchronized();
                segment.SetMemory(_pool.Rent(GetSegmentSize(sizeHint)));
            }

            if (bufferSequence.CommitHead == null)
            {
                // No previous writes have occurred
                bufferSequence.CommitHead = segment;
            }
            else if (segment != bufferSequence.CommitHead && bufferSequence.CommitHead.Next == null)
            {
                // Append the segment to the commit head if writes have been committed
                // and it isn't the same segment (unused tail space)
                bufferSequence.CommitHead.SetNext(segment);
            }

            // Set write head to assigned segment
            bufferSequence.WritingHead = segment;

            return segment;
        }

        internal int GetSegmentSize(int sizeHint)
        {
            // First we need to handle case where hint is smaller than minimum segment size
            var adjustedToMinimumSize = Math.Max(_minimumSegmentSize, sizeHint);
            // After that adjust it to fit into pools max buffer size
            var adjustedToMaximumSize = Math.Min(_pool.MaxBufferSize, adjustedToMinimumSize);
            return adjustedToMaximumSize;
        }

        internal BufferSegment CreateSegmentUnsynchronized()
        {
            if (_pooledSegmentCount > 0)
            {
                _pooledSegmentCount--;
                return _bufferSegmentPool[_pooledSegmentCount];
            }

            return new BufferSegment();
        }

        internal void ReturnSegmentUnsynchronized(BufferSegment segment)
        {
            if (_pooledSegmentCount < _bufferSegmentPool.Length)
            {
                _bufferSegmentPool[_pooledSegmentCount] = segment;
                _pooledSegmentCount++;
            }
        }

        internal bool CommitUnsynchronized(ref BufferSequence bufferSequence, bool actualFlush = true)
        {
            if (bufferSequence.WritingHead == null)
            {
                // Nothing written to commit
                return true;
            }

            if (bufferSequence.ReadHead == null)
            {
                // Update the head to point to the head of the buffer.
                // This happens if we called alloc(0) then write
                bufferSequence.ReadHead = bufferSequence.CommitHead;
                bufferSequence.ReadHeadIndex = 0;
            }

            // Always move the commit head to the write head
            var bytesWritten = bufferSequence.CurrentWriteLength;
            bufferSequence.CommitHead = bufferSequence.WritingHead;
            bufferSequence.CommitHeadIndex = bufferSequence.WritingHead.End;
            bufferSequence.Length += bytesWritten;

            // Do not reset if reader is complete
            if (actualFlush
                && _pauseWriterThreshold > 0
                && bufferSequence.Length >= _pauseWriterThreshold 
                && !_readerCompletion.IsCompleted)
            {
                _writerAwaitable.Reset();
            }

            // Clear the writing state
            bufferSequence.WritingHead = null;
            bufferSequence.CurrentWriteLength = 0;

            return bytesWritten == 0;
        }

        internal abstract void PreProcess(
            ref BufferSequence writerSequence,
            ref BufferSequence sslSequence);

        internal void Advance(int bytesWritten)
        {
            this.AdvanceInternal(bytesWritten, ref this._writerSequence);
        }

        internal abstract void AdvanceInternal(int bytesWritten, ref BufferSequence writerSequence);

        internal void AdvanceInternal(int bytesWritten)
        {
            this.Advance(bytesWritten, ref this._writerSequence);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal void Advance(int bytesWritten, ref BufferSequence bufferSequence)
        {
            if (bufferSequence.WritingHead == null)
            {
                ThrowHelper.ThrowInvalidOperationException_NotWritingNoAlloc();
            }

            if (bytesWritten > 0)
            {
                Debug.Assert(!bufferSequence.WritingHead.ReadOnly);
                Debug.Assert(bufferSequence.WritingHead.Next == null);

                Memory<byte> buffer = bufferSequence.WritingHead.AvailableMemory;

                if (bufferSequence.WritingHead.End > buffer.Length - bytesWritten)
                {
                    ThrowHelper.ThrowInvalidOperationException_AdvancingPastBufferSize();
                }

                bufferSequence.WritingHead.End += bytesWritten;
                bufferSequence.CurrentWriteLength += bytesWritten;
            }
            else if (bytesWritten < 0)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(ExceptionArgument.bytesWritten);
            }

            // and if zero, just do nothing; don't need to validate tail etc
        }

        internal ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken)
        {
            return this.FlushAsyncInternal(cancellationToken, ref this._writerSequence);
        }

        internal abstract ValueTask<FlushResult> FlushAsyncInternal(CancellationToken cancellationToken, ref BufferSequence writerSequence);

        internal ValueTask<FlushResult> FlushAsyncInternal(CancellationToken cancellationToken)
        {
            return this.FlushAsync(cancellationToken, ref this._writerSequence);
        }

        internal ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken, ref BufferSequence bufferSequence) //ref to force overrides
        {
            CompletionData completionData;
            CancellationTokenRegistration cancellationTokenRegistration;
            ValueTask<FlushResult> result;
            lock (_sync)
            {
                bool wasEmpty;

                if (this.CurrentConnection.IsAvailable(out SslState sslState) && sslState == SslState.Established)
                {
                    if (!CommitUnsynchronized(ref this._writerSequence, false))
                    {
                        this.PreProcess(ref this._writerSequence, ref this._readerSequence);
                    }
                }
                else
                {
                    //TODO: remove copy
                    if(!CommitUnsynchronized(ref this._writerSequence, false))
                    {
                        ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(this._writerSequence.ReadHead,
                                                                                     this._writerSequence.ReadHeadIndex,
                                                                                     this._writerSequence.CommitHead,
                                                                                     this._writerSequence.CommitHeadIndex - this._writerSequence.CommitHead.Start);

                        Memory<byte> readerBuffer;
                        if (sequence.IsSingleSegment)
                        {
                            readerBuffer = this.GetMemory(sequence.First.Length, ref this._readerSequence);
                            sequence.First.CopyTo(readerBuffer);
                            this.Advance(sequence.First.Length, ref this._readerSequence);
                        }
                        else
                        {
                            foreach (ReadOnlyMemory<byte> buffer in sequence)
                            {
                                if (buffer.IsEmpty)
                                    continue;

                                readerBuffer = this.GetMemory(sequence.First.Length, ref this._readerSequence);
                                buffer.CopyTo(readerBuffer);
                                this.Advance(buffer.Length, ref this._readerSequence);
                            }
                        }

                        this.AdvanceReader(sequence.End, sequence.End, ref this._writerSequence, false);
                    }
                }

                wasEmpty = this.CommitUnsynchronized(ref this._readerSequence);

                // AttachToken before completing reader awaiter in case cancellationToken is already completed
                cancellationTokenRegistration = this._writerAwaitable.AttachToken(cancellationToken, s_signalWriterAwaitable, this);

                // If the writer is completed (which it will be most of the time) then return a completed ValueTask
                if (this._writerAwaitable.IsCompleted)
                {
                    var flushResult = new FlushResult();
                    GetFlushResult(ref flushResult);
                    result = new ValueTask<FlushResult>(flushResult);
                }
                else
                {
                    result = new ValueTask<FlushResult>(_writer, token: 0);
                }

                // Complete reader only if new data was pushed into the pipe
                if (!wasEmpty)
                {
                    this._readerAwaitable.Complete(out completionData);
                }
                else
                {
                    completionData = default;
                }

                // I couldn't find a way for flush to induce backpressure deadlock
                // if it always adds new data to pipe and wakes up the reader but assert anyway
                Debug.Assert(this._writerAwaitable.IsCompleted || this._readerAwaitable.IsCompleted);
            }

            cancellationTokenRegistration.Dispose();

            TrySchedule(_readerScheduler, completionData);

            return result;
        }

        internal void CompleteWriter(Exception exception)
        {
            CompletionData completionData;
            PipeCompletionCallbacks completionCallbacks;
            bool readerCompleted;

            lock (_sync)
            {
                // Commit any pending buffers
                CommitUnsynchronized(ref this._writerSequence);

                completionCallbacks = _writerCompletion.TryComplete(exception);
                _readerAwaitable.Complete(out completionData);
                readerCompleted = _readerCompletion.IsCompleted;
            }

            if (completionCallbacks != null)
            {
                TrySchedule(_readerScheduler, s_invokeCompletionCallbacks, completionCallbacks);
            }

            TrySchedule(_readerScheduler, completionData);

            if (readerCompleted)
            {
                CompletePipe();
            }
        }

        internal void AdvanceReader(in SequencePosition consumed, bool actualRead = true)
        {
            this.AdvanceReader(consumed, consumed, ref this._readerSequence);
        }

        internal void AdvanceReaderInternal(in SequencePosition consumed, bool actualRead = true)
        {
            this.AdvanceReader(consumed, consumed, ref this._readerSequence);
        }

        internal void AdvanceReader(in SequencePosition consumed, in SequencePosition examined, bool actualRead = true)
        {
            this.AdvanceReader(consumed, examined, ref this._readerSequence);
        }

        internal void AdvanceReader(in SequencePosition consumed, in SequencePosition examined, ref BufferSequence bufferSequence, bool actualRead = true)
        {
            // If the reader is completed
            if (actualRead
                && _readerCompletion.IsCompleted)
            {
                ThrowHelper.ThrowInvalidOperationException_NoReadingAllowed();
            }

            // TODO: Use new SequenceMarshal.TryGetReadOnlySequenceSegment to get the correct data
            // directly casting only works because the type value in ReadOnlySequenceSegment is 0
            AdvanceReader((BufferSegment)consumed.GetObject(), consumed.GetInteger(), (BufferSegment)examined.GetObject(), examined.GetInteger(), ref bufferSequence, actualRead);
        }

        internal void AdvanceReader(BufferSegment consumedSegment, int consumedIndex, BufferSegment examinedSegment, int examinedIndex, ref BufferSequence bufferSequence, bool actualRead = true)
        {
            BufferSegment returnStart = null;
            BufferSegment returnEnd = null;

            CompletionData completionData = default;

            lock (_sync)
            {
                bool isEmpty = bufferSequence.ReadHead == null;
                var examinedEverything = false;

                if (examinedSegment != null)
                {
                    if (isEmpty)
                    {
                        ThrowHelper.ThrowInvalidOperationException_AdvanceToInvalidCursor();
                        return;
                    }

                    examinedEverything = examinedSegment == bufferSequence.CommitHead && examinedIndex == bufferSequence.CommitHeadIndex - bufferSequence.CommitHead.Start;
                }
                else
                {
                    examinedEverything = isEmpty;
                }

                if (consumedSegment != null)
                {
                    if (isEmpty)
                    {
                        ThrowHelper.ThrowInvalidOperationException_AdvanceToInvalidCursor();
                        return;
                    }

                    returnStart = bufferSequence.ReadHead;
                    returnEnd = consumedSegment;

                    // Check if we crossed _maximumSizeLow and complete backpressure
                    long consumedBytes = new ReadOnlySequence<byte>(returnStart, bufferSequence.ReadHeadIndex, consumedSegment, consumedIndex).Length;
                    long oldLength = bufferSequence.Length;
                    bufferSequence.Length -= consumedBytes;

                    if (actualRead
                        && oldLength >= _resumeWriterThreshold
                        && bufferSequence.Length < _resumeWriterThreshold)
                    {
                        this._writerAwaitable.Complete(out completionData);
                    }

                    // Check if we consumed entire last segment
                    // if we are going to return commit head we need to check that there is no writing operation that
                    // might be using tailspace
                    if (consumedIndex == returnEnd.Length && bufferSequence.WritingHead != returnEnd)
                    {
                        BufferSegment nextBlock = returnEnd.NextSegment;
                        if (bufferSequence.CommitHead == returnEnd)
                        {
                            bufferSequence.CommitHead = nextBlock;
                            bufferSequence.CommitHeadIndex = 0;
                        }

                        bufferSequence.ReadHead = nextBlock;
                        bufferSequence.ReadHeadIndex = 0;
                        returnEnd = nextBlock;
                    }
                    else
                    {
                        bufferSequence.ReadHead = consumedSegment;
                        bufferSequence.ReadHeadIndex = consumedIndex;
                    }
                }

                // We reset the awaitable to not completed if we've examined everything the producer produced so far
                // but only if writer is not completed yet
                if (actualRead
                    && examinedEverything && !_writerCompletion.IsCompleted)
                {
                    // Prevent deadlock where reader awaits new data and writer await backpressure
                    if (!_writerAwaitable.IsCompleted)
                    {
                        ThrowHelper.ThrowInvalidOperationException_BackpressureDeadlock();
                    }
                    _readerAwaitable.Reset();
                }

                while (returnStart != null && returnStart != returnEnd)
                {
                    returnStart.ResetMemory();
                    ReturnSegmentUnsynchronized(returnStart);
                    returnStart = returnStart.NextSegment;
                }

                if (actualRead)
                    _readingState.End();
            }

            TrySchedule(_writerScheduler, completionData);
        }

        internal void CompleteReader(Exception exception)
        {
            PipeCompletionCallbacks completionCallbacks;
            CompletionData completionData;
            bool writerCompleted;

            lock (_sync)
            {
                // If we're reading, treat clean up that state before continuting
                if (_readingState.IsActive)
                {
                    _readingState.End();
                }

                // REVIEW: We should consider cleaning up all of the allocated memory
                // on the reader side now.

                CommitUnsynchronized(ref this._readerSequence, false);

                completionCallbacks = _readerCompletion.TryComplete(exception);
                _writerAwaitable.Complete(out completionData);
                writerCompleted = _writerCompletion.IsCompleted;
            }

            if (completionCallbacks != null)
            {
                TrySchedule(_writerScheduler, s_invokeCompletionCallbacks, completionCallbacks);
            }

            TrySchedule(_writerScheduler, completionData);

            if (writerCompleted)
            {
                CompletePipe();
            }
        }

        internal void OnWriterCompleted(Action<Exception, object> callback, object state)
        {
            if (callback == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.callback);
            }

            PipeCompletionCallbacks completionCallbacks;
            lock (_sync)
            {
                completionCallbacks = _writerCompletion.AddCallback(callback, state);
            }

            if (completionCallbacks != null)
            {
                TrySchedule(_readerScheduler, s_invokeCompletionCallbacks, completionCallbacks);
            }
        }

        internal void CancelPendingRead()
        {
            CompletionData completionData;
            lock (_sync)
            {
                _readerAwaitable.Cancel(out completionData);
            }
            TrySchedule(_readerScheduler, completionData);
        }

        internal void CancelPendingFlush()
        {
            CompletionData completionData;
            lock (_sync)
            {
                _writerAwaitable.Cancel(out completionData);
            }
            TrySchedule(_writerScheduler, completionData);
        }

        internal void OnReaderCompleted(Action<Exception, object> callback, object state)
        {
            if (callback == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.callback);
            }

            PipeCompletionCallbacks completionCallbacks;
            lock (_sync)
            {
                completionCallbacks = _readerCompletion.AddCallback(callback, state);
            }

            if (completionCallbacks != null)
            {
                TrySchedule(_writerScheduler, s_invokeCompletionCallbacks, completionCallbacks);
            }
        }

        internal ValueTask<ReadResult> ReadAsync(CancellationToken token)
        {
            return this.ReadAsync(token, ref this._readerAwaitable);
        }

        internal abstract ValueTask<ReadResult> ReadAsync(CancellationToken token, ref PipeAwaitable readerAwaitable);

        internal ValueTask<ReadResult> ReadAsyncInternal(CancellationToken token)
        {
            return this.ReadAsync(token, ref this._readerAwaitable, ref this._readerAwaitable);
        }

        internal ValueTask<ReadResult> ReadAsync(CancellationToken token, ref PipeAwaitable readerAwaitable, ref PipeAwaitable pipeAwaitable)
        {
            CancellationTokenRegistration cancellationTokenRegistration;
            if (_readerCompletion.IsCompleted)
            {
                ThrowHelper.ThrowInvalidOperationException_NoReadingAllowed();
            }

            ValueTask<ReadResult> result;
            lock (_sync)
            {
                cancellationTokenRegistration = pipeAwaitable.AttachToken(token, s_signalReaderAwaitable, this);

                // If the awaitable is already complete then return the value result directly
                if (pipeAwaitable.IsCompleted)
                {
                    var readResult = new ReadResult();
                    GetReadResult(ref readResult, ref this._readerSequence);
                    result = new ValueTask<ReadResult>(readResult);
                }
                else
                {
                    // Otherwise it's async
                    return this.GetReadResultAsync(this._reader, ref pipeAwaitable);
                }
            }
            cancellationTokenRegistration.Dispose();

            return result;
        }

        internal abstract ValueTask<ReadResult> GetReadResultAsync(in IValueTaskSource<ReadResult> pipeReader, ref PipeAwaitable pipeAwaitable);

        internal void StartInterrupt(bool handshake)
        {
            lock (this._sync)
            {
                this.StartInterruptInternal(handshake, ref this._readerAwaitable, ref this._writerSequence, ref this._readerSequence);
            }
        }

        internal abstract void StartInterruptInternal(bool handshake, ref PipeAwaitable readerAwaitable, ref BufferSequence writerSequence, ref BufferSequence sslSequence);

        internal void CompleteInterrupt(bool handshake)
        {
            lock (this._sync)
            {
                this.CompleteInterruptInternal(handshake, ref this._readerAwaitable, ref this._writerSequence, ref this._readerSequence);
            }
        }

        internal abstract void CompleteInterruptInternal(bool handshake, ref PipeAwaitable readerAwaitable, ref BufferSequence writerSequence, ref BufferSequence sslSequence);

        private bool TryRead(out ReadResult result)
        {
            lock (_sync)
            {
                if (_readerCompletion.IsCompleted)
                {
                    ThrowHelper.ThrowInvalidOperationException_NoReadingAllowed();
                }

                result = new ReadResult();

                if (this._readerSequence.Length > 0 || _readerAwaitable.IsCompleted)
                {
                    GetReadResult(ref result, ref this._readerSequence);
                    return true;
                }

                if (_readerAwaitable.HasContinuation)
                {
                    ThrowHelper.ThrowInvalidOperationException_AlreadyReading();
                }
                return false;
            }
        }

        private static void TrySchedule(PipeScheduler scheduler, Action<object> action, object state)
        {
            if (action != null)
            {
                scheduler.Schedule(action, state);
            }
        }

        internal static void TrySchedule(PipeScheduler scheduler, in CompletionData completionData)
        {
            // Nothing to do
            if (completionData.Completion == null)
            {
                return;
            }

            // Ultimately, we need to call either
            // 1. The sync context with a delegate
            // 2. The scheduler with a delegate
            // That delegate and state will either be the action passed in directly
            // or it will be that specified delegate wrapped in ExecutionContext.Run

            if (completionData.SynchronizationContext == null)
            {
                // We don't have a SynchronizationContext so execute on the specified scheduler
                if (completionData.ExecutionContext == null)
                {
                    // We can run directly, this should be the default fast path
                    scheduler.Schedule(completionData.Completion, completionData.CompletionState);
                    return;
                }

                // We also have to run on the specified execution context so run the scheduler and execute the
                // delegate on the execution context
                scheduler.Schedule(s_scheduleWithExecutionContextCallback, completionData);
            }
            else
            {
                if (completionData.ExecutionContext == null)
                {
                    // We need to box the struct here since there's no generic overload for state
                    completionData.SynchronizationContext.Post(s_syncContextExecuteWithoutExecutionContextCallback, completionData);
                }
                else
                {
                    // We need to execute the callback with the execution context
                    completionData.SynchronizationContext.Post(s_syncContextExecutionContextCallback, completionData);
                }
            }
        }

        private static void ExecuteWithoutExecutionContext(object state)
        {
            CompletionData completionData = (CompletionData)state;
            completionData.Completion(completionData.CompletionState);
        }

        private static void ExecuteWithExecutionContext(object state)
        {
            CompletionData completionData = (CompletionData)state;
            Debug.Assert(completionData.ExecutionContext != null);
            ExecutionContext.Run(completionData.ExecutionContext, s_executionContextRawCallback, state);
        }

        private void CompletePipe()
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;

                this.ResetBufferSegment(ref this._writerSequence);
                this.ResetBufferSegment(ref this._readerSequence);
            }
        }

        private void ResetBufferSegment(ref BufferSequence bufferSequence)
        {
            // Return all segments
            // if _readHead is null we need to try return _commitHead
            // because there might be a block allocated for writing
            BufferSegment segment = bufferSequence.ReadHead ?? bufferSequence.CommitHead;
            while (segment != null)
            {
                BufferSegment returnSegment = segment;
                segment = segment.NextSegment;

                returnSegment.ResetMemory();
            }

            bufferSequence.WritingHead = null;
            bufferSequence.ReadHead = null;
            bufferSequence.CommitHead = null;
        }

        internal ValueTaskSourceStatus GetReadAsyncStatus()
        {
            if (_readerAwaitable.IsCompleted)
            {
                if (_writerCompletion.IsFaulted)
                {
                    return ValueTaskSourceStatus.Faulted;
                }

                return ValueTaskSourceStatus.Succeeded;
            }
            return ValueTaskSourceStatus.Pending;
        }

        internal void OnReadAsyncCompleted(Action<object> continuation, object state, ValueTaskSourceOnCompletedFlags flags, ref PipeAwaitable pipeAwaitable)
        {
            CompletionData completionData;
            bool doubleCompletion;
            lock (_sync)
            {
                pipeAwaitable.OnCompleted(continuation, state, flags, out completionData, out doubleCompletion);
            }
            if (doubleCompletion)
            {
                Writer.Complete(ThrowHelper.CreateInvalidOperationException_NoConcurrentOperation());
            }
            TrySchedule(_readerScheduler, completionData);
        }

        internal void OnReadAsyncCompletedInternal(Action<object> continuation, object state, ValueTaskSourceOnCompletedFlags flags)
        {
            this.OnReadAsyncCompleted(continuation, state, flags, ref this._readerAwaitable);
        }

        internal ReadResult GetReadAsyncResult()
        {
            if (!_readerAwaitable.IsCompleted)
            {
                ThrowHelper.ThrowInvalidOperationException_GetResultNotCompleted();
            }

            var result = new ReadResult();
            lock (_sync)
            {
                GetReadResult(ref result, ref this._readerSequence);
            }
            return result;
        }

        private void GetReadResult(ref ReadResult result, ref BufferSequence readSequence)
        {
            if (_writerCompletion.IsCompletedOrThrow())
            {
                result._resultFlags |= ResultFlags.Completed;
            }

            bool isCanceled = _readerAwaitable.ObserveCancelation();
            if (isCanceled)
            {
                result._resultFlags |= ResultFlags.Canceled;
            }

            // No need to read end if there is no head
            BufferSegment head = readSequence.ReadHead;

            if (head != null)
            {
                // Reading commit head shared with writer
                result._resultBuffer = new ReadOnlySequence<byte>(head, readSequence.ReadHeadIndex, readSequence.CommitHead, readSequence.CommitHeadIndex - readSequence.CommitHead.Start);
            }

            if (isCanceled)
            {
                _readingState.BeginTentative();
            }
            else
            {
                _readingState.Begin();
            }
        }

        internal ValueTaskSourceStatus GetFlushAsyncStatus()
        {
            if (_writerAwaitable.IsCompleted)
            {
                if (_readerCompletion.IsFaulted)
                {
                    return ValueTaskSourceStatus.Faulted;
                }

                return ValueTaskSourceStatus.Succeeded;
            }
            return ValueTaskSourceStatus.Pending;
        }

        internal FlushResult GetFlushAsyncResult()
        {
            var result = new FlushResult();
            lock (_sync)
            {
                if (!_writerAwaitable.IsCompleted)
                {
                    ThrowHelper.ThrowInvalidOperationException_GetResultNotCompleted();
                }

                GetFlushResult(ref result);
            }

            return result;
        }

        private void GetFlushResult(ref FlushResult result)
        {
            // Change the state from to be canceled -> observed
            if (_writerAwaitable.ObserveCancelation())
            {
                result._resultFlags |= ResultFlags.Canceled;
            }
            if (_readerCompletion.IsCompletedOrThrow())
            {
                result._resultFlags |= ResultFlags.Completed;
            }
        }

        internal void OnFlushAsyncCompleted(Action<object> continuation, object state, ValueTaskSourceOnCompletedFlags flags)
        {
            CompletionData completionData;
            bool doubleCompletion;
            lock (_sync)
            {
                this._writerAwaitable.OnCompleted(continuation, state, flags, out completionData, out doubleCompletion);
            }
            if (doubleCompletion)
            {
                Reader.Complete(ThrowHelper.CreateInvalidOperationException_NoConcurrentOperation());
            }
            TrySchedule(_writerScheduler, completionData);
        }

        private void ReaderCancellationRequested()
        {
            CompletionData completionData;
            lock (_sync)
            {
                _readerAwaitable.Cancel(out completionData);
            }
            TrySchedule(_readerScheduler, completionData);
        }

        private void WriterCancellationRequested()
        {
            CompletionData completionData;
            lock (_sync)
            {
                _writerAwaitable.Cancel(out completionData);
            }
            TrySchedule(_writerScheduler, completionData);
        }

        /// <summary>
        /// Gets the <see cref="PipeReader"/> for this pipe.
        /// </summary>
        public PipeReader Reader => _reader;

        /// <summary>
        /// Gets the <see cref="PipeWriter"/> for this pipe.
        /// </summary>
        public PipeWriter Writer => _writer;

        /// <summary>
        /// Resets the pipe
        /// </summary>
        public void Reset()
        {
            lock (_sync)
            {
                if (!_disposed)
                {
                    ThrowHelper.ThrowInvalidOperationException_ResetIncompleteReaderWriter();
                }

                _disposed = false;
                ResetState();
            }
        }
    }
}
