using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

using OpenSSL.Core.Interop;

namespace OpenSSL.Core.SSL.PipeLines
{
    internal class SocketPipeReader : PipeReader
    {
        private PipeReader _socketPipeReader;
        private SocketConnection SocketConnection;
        private SocketPipeReaderValueTaskSource ReaderValueTaskSource;

        internal Pipe OutputPipe { get; private set; }

        public SocketPipeReader(Pipe receiveSocketPipe, 
            PipeOptions pipeOptions, 
            SocketConnection socketConnection)
        {
            this._socketPipeReader = receiveSocketPipe.Reader;
            this.SocketConnection = socketConnection;

            this.OutputPipe = new Pipe(pipeOptions);
            this.ReaderValueTaskSource = new SocketPipeReaderValueTaskSource(this, this.SocketConnection, this._socketPipeReader, this.OutputPipe);
        }

        internal void CompleteInterruption()
        {
            this.ReaderValueTaskSource.CompleteInterruption();
        }

        public override void AdvanceTo(SequencePosition consumed)
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"The pipe is occupied by another operation. Current SSL state: {sslState.ToString()}");

            this.OutputPipe.Reader.AdvanceTo(consumed);
        }

        public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"The pipe is occupied by another operation. Current SSL state: {sslState.ToString()}");

            this.OutputPipe.Reader.AdvanceTo(consumed, examined);
        }

        public override void CancelPendingRead()
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"The pipe is occupied by another operation. Current SSL state: {sslState.ToString()}");

            this.OutputPipe.Reader.CancelPendingRead();
        }

        public override void Complete(Exception exception = null)
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException($"The pipe is occupied by another operation. Current SSL state: {sslState.ToString()}");

            this.OutputPipe.Reader.Complete(exception);
            this.OutputPipe.Writer.Complete(exception);
        }

        public override void OnWriterCompleted(Action<Exception, object> callback, object state)
        {
            this.OutputPipe.Reader.OnWriterCompleted(callback, state);
        }

        public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
        {
            return this.ReaderValueTaskSource.RunAsync(cancellationToken);
        }

        internal bool ConsumeSocketReadResult(SslState sslState, in ReadResult readResult, CancellationToken cancellationToken = default)
        {
            ReadOnlySequence<byte> buffer = readResult.Buffer;
            SequencePosition advanceTo;

            //TODO: throw error?
            if (buffer.IsEmpty)
                return false;

            if (sslState == SslState.None)
                advanceTo = this.ConsumeSocketData(buffer);
            else if (sslState == SslState.Established)
            {
                if (!this.ConsumeSocketSslData(readResult, out advanceTo))
                {
                    this._socketPipeReader.AdvanceTo(advanceTo);
                    return false;
                }
            }
            else
                throw new InvalidOperationException("Connection in an invalid SSL state");

            this._socketPipeReader.AdvanceTo(advanceTo);
            return true;
        }

        private SequencePosition ConsumeSocketData(in ReadOnlySequence<byte> buffer)
        {
            if (buffer.IsSingleSegment)
                this.OutputPipe.Writer.Write(buffer.First.Span); //TODO: this is a copy
            else
            {
                foreach (ReadOnlyMemory<byte> segment in buffer)
                {
                    if (segment.IsEmpty)
                        continue;

                    this.OutputPipe.Writer.Write(segment.Span); //TODO: this is a copy
                }
            }

            return buffer.End;
        }

        private bool ConsumeSocketSslData(in ReadResult socketResult, out SequencePosition endPosition)
        {
            ReadOnlySequence<byte> sequence, readSequence;
            SequencePosition position;
            FrameType frameType;
            int lengthWithHead, decryptedRead;
            Memory<byte> writeBuffer;
            endPosition = default;

            sequence = socketResult.Buffer;
            endPosition = socketResult.Buffer.Start;

            if (sequence.IsEmpty)
                return false;

            //TODO: remove frame parsing and trust BIO writes
            while (SocketConnection.ParseFrame(sequence, out position, out lengthWithHead, out frameType))
            {
                //also allow alert frames
                //if (frameType != FrameType.Application)
                //    throw new InvalidOperationException("Invalid SSL frame type detected");

                readSequence = sequence.Slice(0, position);

                //write what was read from the other party to the BIO
                if (readSequence.IsSingleSegment)
                    this.SocketConnection.WriteToSslBio(readSequence.First);
                else
                {
                    foreach (ReadOnlyMemory<byte> memory in readSequence)
                        this.SocketConnection.WriteToSslBio(memory);
                }

                //assign current read position
                endPosition = readSequence.End;

                //progress through the current sequence
                sequence = sequence.Slice(position);
            }

            //no data has been read
            if (endPosition.Equals(socketResult.Buffer.Start))
                return false;

            //decrypt the read data
            do
            {
                writeBuffer = this.OutputPipe.Writer.GetMemory(Native.SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER);
                decryptedRead = this.SocketConnection.ReadFromSsl(writeBuffer);
                this.OutputPipe.Writer.Advance(decryptedRead);
            } while (decryptedRead > 0);

            return true;
        }

        //TODO: see ReadAsync (remember ValueTask?)
        public override bool TryRead(out ReadResult result)
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                return false;

            return this.OutputPipe.Reader.TryRead(out result);
        }
    }
}
