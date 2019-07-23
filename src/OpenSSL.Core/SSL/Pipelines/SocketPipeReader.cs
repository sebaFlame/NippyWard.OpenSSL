using System;
using System.Collections.Generic;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;
using System.Runtime.CompilerServices;

using OpenSSL.Core.Interop;

namespace OpenSSL.Core.SSL.Pipelines
{
    internal sealed class SocketPipeReader : Pipe
    {
        private PipeAwaitable _readerInterruptAwaitable;

        public SocketPipeReader(PipeOptions pipeOptions, SocketConnection socketConnection)
            : base(pipeOptions, socketConnection)
        {
            var useSynchronizationContext = pipeOptions.UseSynchronizationContext;
            this._readerInterruptAwaitable = new PipeAwaitable(completed: false, useSynchronizationContext);
        }

        internal override void PreProcess(ref BufferSequence writerSequence, ref BufferSequence sslSequence)
        {
            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(writerSequence.ReadHead, writerSequence.ReadHeadIndex, writerSequence.CommitHead, writerSequence.CommitHeadIndex - writerSequence.CommitHead.Start);
            long totalDecrypted = 0;

            //write what was read from the other party to the BIO
            if (sequence.IsSingleSegment)
            {
                this.CurrentConnection.WriteToSslBio(sequence.First);

                //decrypt the read data
                totalDecrypted += this.DecryptSocketData(ref sslSequence);
            }
            else
            {
                foreach (ReadOnlyMemory<byte> buffer in sequence)
                {
                    if (buffer.IsEmpty)
                        continue;

                    this.CurrentConnection.WriteToSslBio(buffer);

                    //decrypt the read data
                    totalDecrypted += this.DecryptSocketData(ref sslSequence);
                }
            }

            this.AdvanceReader(sequence.End, sequence.End, ref writerSequence, false);
        }

        private long DecryptSocketData(ref BufferSequence decryptSequence)
        {
            Memory<byte> buffer;
            long totalDecrypted = 0;
            int consumed, pending = 0;

            do
            {
                buffer = this.GetMemory(Native.SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER, ref decryptSequence);
                totalDecrypted += (consumed = this.CurrentConnection.ReadFromSsl(buffer, out pending));
                this.Advance(consumed, ref decryptSequence);
            } while (consumed > 0 && pending > 0);

            return totalDecrypted;
        }

        internal override Memory<byte> GetMemoryInternal(int sizeHint, ref BufferSequence writerSequence)
        {
            return this.GetMemory(sizeHint, ref writerSequence);
        }

        internal override void AdvanceInternal(int bytesWritten, ref BufferSequence writerSequence)
        {
            this.Advance(bytesWritten, ref writerSequence);
        }

        internal override ValueTask<FlushResult> FlushAsyncInternal(CancellationToken cancellationToken, ref BufferSequence writerSequence)
        {
            return this.FlushAsync(cancellationToken, ref writerSequence);
        }

        internal override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken, ref PipeAwaitable readerAwaitable)
        {
            if (!this.CurrentConnection.IsAvailable(out SslState sslState))
                return this.ReadAsync(cancellationToken, ref readerAwaitable, ref this._readerInterruptAwaitable);

            return this.ReadAsync(cancellationToken, ref readerAwaitable, ref readerAwaitable);
        }

        internal override ValueTask<ReadResult> GetReadResultAsync(in IValueTaskSource<ReadResult> pipeReader, ref PipeAwaitable pipeAwaitable)
        {
            if (Unsafe.AreSame(ref pipeAwaitable, ref this._readerInterruptAwaitable))
                return new ValueTask<ReadResult>(new DefaultInterruptedPipeReader(this), token: 0);
            else
                return new ValueTask<ReadResult>(pipeReader, token: 0);
        }

        internal override void StartInterruptInternal(bool handshake, ref PipeAwaitable readerAwaitable, ref BufferSequence writerSequence, ref BufferSequence sslSequence)
        {
            if (readerAwaitable.HasContinuation
                    && !readerAwaitable.IsCompleted)
            {
                this._readerInterruptAwaitable.Copy(readerAwaitable);
                readerAwaitable.Complete(out _);
                readerAwaitable.Reset();
            }
        }

        internal override void CompleteInterruptInternal(bool handshake, ref PipeAwaitable readerAwaitable, ref BufferSequence writerSequence, ref BufferSequence sslSequence)
        {
            if (this._readerInterruptAwaitable.HasContinuation
                && !this._readerInterruptAwaitable.IsCompleted)
            {
                readerAwaitable.Copy(this._readerInterruptAwaitable);
                this._readerInterruptAwaitable.Complete(out _);
                this._readerInterruptAwaitable.Reset();
            }
        }

        internal ValueTaskSourceStatus GetReadAsyncInterruptedStatus()
        {
            if (!this.CurrentConnection.IsAvailable(out SslState sslState))
                return ValueTaskSourceStatus.Pending;

            return this.GetReadAsyncStatus();
        }

        internal void OnReadAsyncInterruptedCompleted(Action<object> continuation, object state, ValueTaskSourceOnCompletedFlags flags)
        {
            this.OnReadAsyncCompleted(continuation, state, flags, ref this._readerInterruptAwaitable);
        }

        private sealed class DefaultInterruptedPipeReader : IValueTaskSource<ReadResult>
        {
            private readonly SocketPipeReader _pipe;

            public DefaultInterruptedPipeReader(SocketPipeReader pipe)
            {
                _pipe = pipe;
            }

            public ValueTaskSourceStatus GetStatus(short token) => _pipe.GetReadAsyncInterruptedStatus();

            public ReadResult GetResult(short token) => _pipe.GetReadAsyncResult();

            public void OnCompleted(Action<object> continuation, object state, short token, ValueTaskSourceOnCompletedFlags flags) => _pipe.OnReadAsyncInterruptedCompleted(continuation, state, flags);
        }
    }
}
