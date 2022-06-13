﻿using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace OpenSSL.Core.SSL.Buffer
{
    //loosely based on System.IO.Pipelines.Pipe
    public class TlsBuffer : IBufferWriter<byte>
    {
        public long Length => this._unconsumedBytes;

        private MemoryPool<byte> _pool;
        private bool _isDefaultSharedMemoryPool;

        // Mutable struct! Don't make this readonly
        private TlsBufferSegmentStack _bufferSegmentPool;

        // The number of bytes flushed but not consumed by the reader
        private long _unconsumedBytes;

        // Stores the last examined position, used to calculate how many bytes were to release
        // for back pressure management
        private long _lastExaminedIndex = -1;

        // The read head which is the start of the PipeReader's consumed bytes
        private TlsBufferSegment? _readHead;
        private int _readHeadIndex;

        // The extent of the bytes available to the PipeReader to consume
        private TlsBufferSegment? _readTail;
        private int _readTailIndex;

        // The write head which is the extent of the PipeWriter's written bytes
        private TlsBufferSegment? _writingHead;
        private Memory<byte> _writingHeadMemory;

        private const int _MinimumSegmentSize = 4096;
        private const int _MaxSegmentPoolSize = 256;
        private const int _InitialSegmentPoolSize = 4;

        public TlsBuffer(MemoryPool<byte> pool)
        {
            this._pool = pool ?? MemoryPool<byte>.Shared;            
            this._bufferSegmentPool = new TlsBufferSegmentStack(_InitialSegmentPoolSize);
            this._isDefaultSharedMemoryPool = pool == MemoryPool<byte>.Shared;
        }

        public TlsBuffer()
            : this(MemoryPool<byte>.Shared)
        { }

        #region IBufferWriter
        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            this.AllocateWriteHeadIfNeeded(sizeHint);

            return this._writingHeadMemory;
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            this.AllocateWriteHeadIfNeeded(sizeHint);

            return this._writingHeadMemory.Span;
        }

        public void Advance(int count)
        {
            this._unconsumedBytes += count;
            this._writingHeadMemory = this._writingHeadMemory.Slice(count);

            this._writingHead.End += count;

            // Always move the read tail to the write head
            this._readTail = this._writingHead;
            this._readTailIndex = this._writingHead.End;
        }
        #endregion

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void AllocateWriteHeadIfNeeded(int sizeHint)
        {
            if (_writingHeadMemory.Length == 0 || _writingHeadMemory.Length < sizeHint)
            {
                this.AllocateWriteHeadSynchronized(sizeHint);
            }
        }

        private void AllocateWriteHeadSynchronized(int sizeHint)
        {
            if (this._writingHead == null)
            {
                // We need to allocate memory to write since nobody has written before
                TlsBufferSegment newSegment = this.AllocateSegment(sizeHint);

                // Set all the pointers
                this._writingHead = this._readHead = this._readTail = newSegment;
                this._lastExaminedIndex = 0;
            }
            else
            {
                int bytesLeftInBuffer = this._writingHeadMemory.Length;

                if (bytesLeftInBuffer == 0 || bytesLeftInBuffer < sizeHint)
                {
                    TlsBufferSegment newSegment = this.AllocateSegment(sizeHint);

                    this._writingHead.SetNext(newSegment);
                    this._writingHead = newSegment;
                }
            }
        }

        private TlsBufferSegment AllocateSegment(int sizeHint)
        {
            TlsBufferSegment newSegment = this.CreateSegmentUnsynchronized();

            MemoryPool<byte>? pool = null;
            int maxSize = -1;

            if (!this._isDefaultSharedMemoryPool)
            {
                pool = this._pool;
                maxSize = pool.MaxBufferSize;
            }

            if (sizeHint <= maxSize)
            {
                // Use the specified pool as it fits. Specified pool is not null as maxSize == -1 if _pool is null.
                newSegment.SetOwnedMemory(pool!.Rent(this.GetSegmentSize(sizeHint, maxSize)));
            }
            else
            {
                // Use the array pool
                int sizeToRequest = this.GetSegmentSize(sizeHint);
                newSegment.SetOwnedMemory(ArrayPool<byte>.Shared.Rent(sizeToRequest));
            }

            _writingHeadMemory = newSegment.AvailableMemory;

            return newSegment;
        }

        private int GetSegmentSize(int sizeHint, int maxBufferSize = int.MaxValue)
        {
            // First we need to handle case where hint is smaller than minimum segment size
            sizeHint = Math.Max(_MinimumSegmentSize, sizeHint);
            // After that adjust it to fit into pools max buffer size
            int adjustedToMaximumSize = Math.Min(maxBufferSize, sizeHint);
            return adjustedToMaximumSize;
        }

        private TlsBufferSegment CreateSegmentUnsynchronized()
        {
            if (this._bufferSegmentPool.TryPop(out TlsBufferSegment? segment))
            {
                return segment;
            }

            return new TlsBufferSegment();
        }

        /// <summary>
        /// Advance inner buffer to <paramref name="consumed"/>
        /// </summary>
        /// <param name="consumed">The position to advance the inner buffer to</param>
        public void AdvanceReader(SequencePosition consumed)
        {
            this.AdvanceReader(consumed, consumed);
        }

        public void AdvanceReader(SequencePosition consumed, SequencePosition examined)
        {
            this.AdvanceReader((TlsBufferSegment?)consumed.GetObject(), consumed.GetInteger(), (TlsBufferSegment?)examined.GetObject(), examined.GetInteger());
        }

        private void AdvanceReader(TlsBufferSegment? consumedSegment, int consumedIndex, TlsBufferSegment? examinedSegment, int examinedIndex)
        {
            // Throw if examined < consumed
            if (consumedSegment != null && examinedSegment != null && TlsBufferSegment.GetLength(consumedSegment, consumedIndex, examinedSegment, examinedIndex) < 0)
            {
                throw new InvalidOperationException("Invalid examined or consumed position");
            }

            TlsBufferSegment? returnStart = null;
            TlsBufferSegment? returnEnd = null;

            bool examinedEverything = false;
            if (examinedSegment == this._readTail)
            {
                examinedEverything = examinedIndex == this._readTailIndex;
            }

            if (examinedSegment != null && _lastExaminedIndex >= 0)
            {
                long examinedBytes = TlsBufferSegment.GetLength(_lastExaminedIndex, examinedSegment, examinedIndex);
                long oldLength = this._unconsumedBytes;

                if (examinedBytes < 0)
                {
                    throw new InvalidOperationException("Invalid examined position");
                }

                this._unconsumedBytes -= examinedBytes;

                // Store the absolute position
                this._lastExaminedIndex = examinedSegment.RunningIndex + examinedIndex;
            }

            if (consumedSegment != null)
            {
                if (this._readHead == null)
                {
                    throw new InvalidOperationException("Advanced to invalid cursor");
                }

                returnStart = _readHead;
                returnEnd = consumedSegment;

                void MoveReturnEndToNextBlock()
                {
                    TlsBufferSegment? nextBlock = returnEnd!.NextSegment;
                    if (this._readTail == returnEnd)
                    {
                        this._readTail = nextBlock;
                        this._readTailIndex = 0;
                    }

                    this._readHead = nextBlock;
                    this._readHeadIndex = 0;

                    returnEnd = nextBlock;
                }

                if (consumedIndex == returnEnd.Length)
                {
                    // If the writing head isn't block we're about to return, then we can move to the next one
                    // and return this block safely
                    if (this._writingHead != returnEnd)
                    {
                        MoveReturnEndToNextBlock();
                    }
                    else
                    {
                        this._readHead = consumedSegment;
                        this._readHeadIndex = consumedIndex;
                    }
                }
                else
                {
                    this._readHead = consumedSegment;
                    this._readHeadIndex = consumedIndex;
                }
            }

            while (returnStart != null && returnStart != returnEnd)
            {
                TlsBufferSegment? next = returnStart.NextSegment;
                returnStart.ResetMemory();
                this.ReturnSegmentUnsynchronized(returnStart);
                returnStart = next;
            }
        }

        private void ReturnSegmentUnsynchronized(TlsBufferSegment segment)
        {
            if (_bufferSegmentPool.Count < _MaxSegmentPoolSize)
            {
                _bufferSegmentPool.Push(segment);
            }
        }

        /// <summary>
        /// Create a <see cref="ReadOnlySequence{T}"/> from the unread buffer
        /// </summary>
        public void CreateReadOnlySequence(out ReadOnlySequence<byte> readOnlySequence)
        {
            // No need to read end if there is no head
            TlsBufferSegment? head = this._readHead;
            if (head != null)
            {
                // Reading commit head shared with writer
                readOnlySequence = new ReadOnlySequence<byte>
                (
                    head,
                    this._readHeadIndex,
                    this._readTail,
                    this._readTailIndex
                );
            }
            else
            {
                readOnlySequence = default;
            }
        }
    }
}
