using System;
using System.Collections.Generic;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

using OpenSSL.Core.Interop;
using System.Threading.Tasks.Sources;

namespace OpenSSL.Core.SSL.Pipelines
{
    internal sealed class SocketPipeWriter : Pipe
    {
        public SocketPipeWriter(PipeOptions pipeOptions, SocketConnection socketConnection)
            : base(pipeOptions, socketConnection)
        {  }

        internal override void PreProcess(ref BufferSequence writerSequence, ref BufferSequence sslSequence)
        {
            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(writerSequence.ReadHead, writerSequence.ReadHeadIndex, writerSequence.CommitHead, writerSequence.CommitHeadIndex - writerSequence.CommitHead.Start);
            long totalEncrypted = 0;

            //encrypt data
            if (sequence.IsSingleSegment)
            {
                totalEncrypted += this.EncryptSocketData(sequence.First, ref sslSequence);
            }
            else
            {
                foreach (ReadOnlyMemory<byte> buffer in sequence)
                {
                    if (buffer.IsEmpty)
                        continue;

                    totalEncrypted += this.EncryptSocketData(buffer, ref sslSequence);
                }
            }

            this.AdvanceReader(sequence.End, sequence.End, ref writerSequence, false);
        }

        private long EncryptSocketData(in ReadOnlyMemory<byte> buffer, ref BufferSequence defaultSequence)
        {
            int totalWritten = 0;
            long totalEncrypted = 0;

            do
            {
                totalWritten += this.CurrentConnection.WriteToSsl(buffer, totalWritten);
                totalEncrypted += this.EncryptSocketData(ref defaultSequence);
            } while (totalWritten < buffer.Length);

            return totalEncrypted;
        }

        private long EncryptSocketData(ref BufferSequence defaultSequence)
        {
            int pending = this.CurrentConnection.ReadFromSslBio(Memory<byte>.Empty, out _);
            Memory<byte> buffer;
            long read = 0;
            int consumed;

            if (pending == 0)
                return 0;

            do
            {
                buffer = this.GetMemory(pending, ref defaultSequence);
                read += (consumed = this.CurrentConnection.ReadFromSslBio(buffer, out pending));
                this.Advance(consumed, ref defaultSequence);
            } while (pending > 0);

            return read;
        }

        internal override Memory<byte> GetMemoryInternal(int sizeHint, ref BufferSequence writerSequence)
        {
            if (!this.CurrentConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"Pipe in invalid state {sslState}");

            return this.GetMemory(sizeHint, ref writerSequence);
        }

        internal override void AdvanceInternal(int bytesWritten, ref BufferSequence writerSequence)
        {
            if (!this.CurrentConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"Pipe in invalid state {sslState}");

            this.Advance(bytesWritten, ref writerSequence);
        }

        internal override ValueTask<FlushResult> FlushAsyncInternal(CancellationToken cancellationToken, ref BufferSequence writerSequence)
        {
            if (!this.CurrentConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"Pipe in invalid state {sslState}");

            return this.FlushAsync(cancellationToken, ref writerSequence);
        }

        internal override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken, ref PipeAwaitable readerAwaitable)
        {
            return this.ReadAsync(cancellationToken, ref readerAwaitable, ref readerAwaitable);
        }

        internal override ValueTask<ReadResult> GetReadResultAsync(in IValueTaskSource<ReadResult> pipeReader, ref PipeAwaitable pipeAwaitable)
        {
            return new ValueTask<ReadResult>(pipeReader, token: 0);
        }

        internal override void StartInterruptInternal(bool handshake, ref PipeAwaitable readerAwaitable, ref BufferSequence writerSequence, ref BufferSequence sslSequence)
        {
            //NOP
        }

        internal override void CompleteInterruptInternal(bool handshake, ref PipeAwaitable readerAwaitable, ref BufferSequence writerSequence, ref BufferSequence sslSequence)
        {
            //NOP
        }
    }
}
