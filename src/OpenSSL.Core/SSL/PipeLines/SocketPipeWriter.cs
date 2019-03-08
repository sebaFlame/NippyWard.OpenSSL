using System;
using System.Collections.Generic;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;

using OpenSSL.Core.Interop;

namespace OpenSSL.Core.SSL.PipeLines
{
    internal class SocketPipeWriter : PipeWriter
    {
        private PipeWriter _socketPipeWriter;
        private SocketConnection SocketConnection;
        private SocketPipeWriterValueTaskSource WriterValueTaskSource;

        internal Pipe InputPipe { get; private set; }

        public SocketPipeWriter(Pipe sendSocketPipe,
            PipeOptions pipeOptions,
            SocketConnection socketConnection)
        {
            this._socketPipeWriter = sendSocketPipe.Writer;
            this.SocketConnection = socketConnection;

            this.InputPipe = new Pipe(pipeOptions);
            this.WriterValueTaskSource = new SocketPipeWriterValueTaskSource(this, this.SocketConnection, this._socketPipeWriter, this.InputPipe);
        }

        internal void CompleteInterruption()
        {
            this.WriterValueTaskSource.CompleteInterruption();
        }

        public override void Advance(int bytes)
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"The pipe is occupied by another operation. Current SSL state: {sslState.ToString()}");

            this.InputPipe.Writer.Advance(bytes);
        }

        public override void CancelPendingFlush()
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"The pipe is occupied by another operation. Current SSL state: {sslState.ToString()}");

            this.InputPipe.Writer.CancelPendingFlush();
        }

        public override void Complete(Exception exception = null)
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"The pipe is occupied by another operation. Current SSL state: {sslState.ToString()}");

            this.InputPipe.Writer.Complete(exception);
            this.InputPipe.Reader.Complete(exception);
        }

        public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
        {
            return this.WriterValueTaskSource.RunAsync(cancellationToken);
        }

        internal bool ConsumeInputReadResult(SslState sslState, in ReadResult readResult, CancellationToken cancellationToken = default)
        {
            ReadOnlySequence<byte> buffer = readResult.Buffer;
            SequencePosition advanceTo;

            //TODO: throw error?
            if (buffer.IsEmpty)
                return false;

            if (sslState == SslState.None)
                advanceTo = this.ConsumeWriterData(buffer);
            else if (sslState == SslState.Established)
                advanceTo = this.ConsumeWriterSslData(buffer);
            else
                throw new InvalidOperationException("Connection in an invalid SSL state");

            //advance clear text reader
            this.InputPipe.Reader.AdvanceTo(advanceTo);
            return true;
        }

        internal SequencePosition ConsumeWriterData(ReadOnlySequence<byte> buffer)
        {
            if (buffer.IsSingleSegment)
                this._socketPipeWriter.Write(buffer.First.Span); //TODO: this is a copy
            else
            {
                foreach (ReadOnlyMemory<byte> segment in buffer)
                {
                    if (segment.IsEmpty)
                        continue;

                    this._socketPipeWriter.Write(segment.Span); //TODO: this is a copy
                }
            }

            return buffer.End;
        }

        internal SequencePosition ConsumeWriterSslData(ReadOnlySequence<byte> buffer)
        {
            int read, written = 0;
            Memory<byte> writeBuffer;

            if (buffer.IsSingleSegment)
                written = this.SocketConnection.WriteToSsl(buffer.First);
            else
            {
                foreach (ReadOnlyMemory<byte> segment in buffer)
                {
                    if (segment.IsEmpty)
                        continue;

                    written += this.SocketConnection.WriteToSsl(segment);
                }
            }

            if (written < buffer.Length)
                throw new ArgumentOutOfRangeException("The buffer has only been written partially");

            do
            {
                writeBuffer = this._socketPipeWriter.GetMemory(Native.SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER);
                read = this.SocketConnection.ReadFromSslBio(writeBuffer);
                this._socketPipeWriter.Advance(read > 0 ? read : 0);
            } while (read > 0);

            return buffer.End;
        }

        public override Memory<byte> GetMemory(int sizeHint = 0)
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"The pipe is occupied by another operation. Current SSL state: {sslState.ToString()}");

            return this.InputPipe.Writer.GetMemory(sizeHint);
        }

        public override Span<byte> GetSpan(int sizeHint = 0)
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"The pipe is occupied by another operation. Current SSL state: {sslState.ToString()}");

            return this.InputPipe.Writer.GetSpan(sizeHint);
        }

        public override void OnReaderCompleted(Action<Exception, object> callback, object state)
        {
            this.InputPipe.Writer.OnReaderCompleted(callback, state);
        }
    }
}
