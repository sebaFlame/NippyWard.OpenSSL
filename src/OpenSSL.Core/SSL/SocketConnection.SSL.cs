using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.IO.Pipelines;
using System.Buffers;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using System.Runtime.CompilerServices;

namespace OpenSSL.Core.SSL
{
    /* TODO
     * check for renegotiation
     * check for shutdown
    */
    public partial class SocketConnection
    {
        #region native handles
        private SafeSslContextHandle sslContextHandle;
        private SafeBioHandle readHandle;
        private SafeBioHandle writeHandle;
        private SafeSslHandle sslHandle;
        private SafeSslSessionHandle sessionHandle;
        #endregion

        #region SSL fields
        private bool encryptionEnabled => this.SslState == SslState.Established;

        private int _sslState;
        internal SslState SslState
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                return (SslState)Thread.VolatileRead(ref this._sslState);
            }
        }
        private bool TrySetSslState(SslState expectedState, SslState newValue) => Interlocked.CompareExchange(ref this._sslState, (int)newValue, (int)expectedState) == (int)expectedState;
        #endregion

        #region Supported Ciphers
        //TODO: doesn't exists anymore
        private static HashSet<string> supportedCiphers;
        public static HashSet<string> SupportedCiphers
        {
            get
            {
                if (!(supportedCiphers is null))
                    return supportedCiphers;

                SafeSslContextHandle ctx;
                SafeStackHandle<SafeSslCipherHandle> sk;
                supportedCiphers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                using (ctx = Native.SSLWrapper.SSL_CTX_new(SafeSslMethodHandle.DefaultServerMethod))
                {
                    using (sk = Native.SSLWrapper.SSL_CTX_get_ciphers(ctx))
                    {
                        foreach (SafeSslCipherHandle c in sk)
                            supportedCiphers.Add(Native.PtrToStringAnsi(Native.SSLWrapper.SSL_CIPHER_get_name(c), false));
                    }
                }

                return supportedCiphers;
            }
        }
        #endregion

        public string Cipher
        {
            get
            {
                if (!this.encryptionEnabled)
                    throw new InvalidOperationException("Encryption has not been enabled yet");

                using (SafeSslCipherHandle cipher = this.SSLWrapper.SSL_get_current_cipher(this.sslHandle))
                    return Native.PtrToStringAnsi(this.SSLWrapper.SSL_CIPHER_get_name(cipher), false);
            }
        }

        public SslProtocol Protocol
        {
            get
            {
                if (!this.encryptionEnabled)
                    throw new InvalidOperationException("Encryption has not been enabled yet");

                int versionNumber = this.SSLWrapper.SSL_version(this.sslHandle);
                SslVersion version = (SslVersion)versionNumber;
                switch (version)
                {
                    case SslVersion.SSL3_VERSION:
                        return SslProtocol.Ssl3;
                    case SslVersion.TLS1_VERSION:
                        return SslProtocol.Tls;
                    case SslVersion.TLS1_1_VERSION:
                        return SslProtocol.Tls11;
                    case SslVersion.TLS1_2_VERSION:
                        return SslProtocol.Tls12;
                    case SslVersion.TLS1_3_VERSION:
                        return SslProtocol.Tls13;
                }

                throw new NotSupportedException("Unknown protocol detected");
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal bool IsAvailable(out SslState sslState)
        {
            return (sslState = this.SslState) <= SslState.Established;
        }

        internal static bool ParseFrame(ReadOnlySequence<byte> sequence, out SequencePosition currentPosition, out int lengthWithHeader, out FrameType frameType)
        {
            lengthWithHeader = 0;
            frameType = FrameType.Alert;
            currentPosition = default;

            if (sequence.Length < 5)
                return false;

            if (sequence.IsSingleSegment)
            {
                frameType = (FrameType)sequence.First.Span[0];
                lengthWithHeader = ((sequence.First.Span[3] << 8) | sequence.First.Span[4]) + 5;

                if (lengthWithHeader > sequence.Length)
                    return false;

                currentPosition = sequence.GetPosition(lengthWithHeader);
                return true;
            }

            int position = 0;
            byte lengthStart = 0;
            foreach (ReadOnlyMemory<byte> memory in sequence)
            {
                if (position == 0)
                    frameType = (FrameType)sequence.First.Span[0];
                else if (position >= 3)
                    lengthStart = memory.Span[3];
                else if (position >= 4)
                {
                    lengthWithHeader = ((lengthStart << 8) | memory.Span[4]) + 5;

                    if (lengthWithHeader > sequence.Length)
                        return false;

                    currentPosition = sequence.GetPosition(lengthWithHeader);
                    return true;
                }

                position += memory.Length;
            }

            return false;
        }

        internal int WriteToSslBio(ReadOnlyMemory<byte> readBuffer)
        {
            int read = this.CryptoWrapper.BIO_write(this.readHandle, readBuffer.Span.GetPinnableReference(), readBuffer.Length);

            if(read < readBuffer.Length)
                throw new ArgumentOutOfRangeException("Data not correctly written to BIO"); //TODO: undo operation / advance pipe?

            return read;
        }

        internal int ReadFromSsl(Memory<byte> writeBuffer)
        {
            int read = this.SSLWrapper.SSL_read(this.sslHandle, ref writeBuffer.Span.GetPinnableReference(), writeBuffer.Length);

            //TODO: manage shutdown/renegotiate

            if (read > 0)
                return read;

            //TODO: error handling incorrect
            int errorCode = this.SSLWrapper.SSL_get_error(this.sslHandle, read);
            SslError error = (SslError)errorCode;

            if (error == SslError.SSL_ERROR_WANT_READ)
                return 0;

            throw new InvalidOperationException($"SSL error: {error.ToString()}");
        }

        internal int WriteToSsl(ReadOnlyMemory<byte> readBuffer)
        {
            int written = this.SSLWrapper.SSL_write(this.sslHandle, readBuffer.Span.GetPinnableReference(), readBuffer.Length);

            //should not happen with PARTIAL_WRITE enabled
            if(written < readBuffer.Length)
                throw new ArgumentOutOfRangeException("Data not correctly written to SSL"); //TODO: undo operation / advance pipe?

            if (written > 0)
                return written;

            //TODO: error handling incorrect
            int errorCode = this.SSLWrapper.SSL_get_error(this.sslHandle, written);
            SslError error = (SslError)errorCode;

            if (error == SslError.SSL_ERROR_WANT_WRITE)
                return 0;

            throw new InvalidOperationException($"SSL error: {error.ToString()}");
        }

        internal int ReadFromSslBio(Memory<byte> writeBuffer)
        {
            return this.CryptoWrapper.BIO_read(this.writeHandle, ref writeBuffer.Span.GetPinnableReference(), writeBuffer.Length);
        }

        private ValueTask<FlushResult> WritePending()
        {
            uint waiting;
            int read;
            Memory<byte> writeBuffer;

            while ((waiting = this.CryptoWrapper.BIO_ctrl_pending(this.writeHandle)) > 0)
            {
                //get a buffer from the writer pool
                writeBuffer = this._sendToSocket.Writer.GetMemory(Native.SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER);

                //read what needs to be sent to the other party
                read = this.CryptoWrapper.BIO_read(this.writeHandle, ref writeBuffer.Span.GetPinnableReference(), writeBuffer.Length);

                //advance writer
                this._sendToSocket.Writer.Advance(read);
            }

            return this._sendToSocket.Writer.FlushAsync();
        }

        private async Task ReadPending(SslError sslError)
        {
            ReadResult readResult;
            ReadOnlySequence<byte> sequence, readSequence;
            SequencePosition position, endPosition = default;
            FrameType frameType;
            int lengthWithHead;

            if (sslError != SslError.SSL_ERROR_WANT_READ)
                return;

            ValueTask<ReadResult> readResultTask = this._receiveFromSocket.Reader.ReadAsync();
            if (!readResultTask.IsCompleted)
                readResult = await readResultTask.ConfigureAwait(false);
            else
                readResult = readResultTask.Result;

            sequence = readResult.Buffer;
            endPosition = sequence.Start;

            if (sequence.IsEmpty)
            {
                this._receiveFromSocket.Reader.AdvanceTo(endPosition);
                return;
            }

            while (ParseFrame(sequence, out position, out lengthWithHead, out frameType))
            {
                //if (frameType != FrameType.Handshake)
                //    return;

                readSequence = sequence.Slice(0, position);

                //write what was read from the other party
                if (readSequence.IsSingleSegment)
                    this.CryptoWrapper.BIO_write(this.readHandle, readSequence.First.Span.GetPinnableReference(), (int)readSequence.First.Length);
                else
                {
                    foreach (ReadOnlyMemory<byte> memory in readSequence)
                        this.CryptoWrapper.BIO_write(this.readHandle, memory.Span.GetPinnableReference(), memory.Length);
                }

                endPosition = readSequence.End;
                sequence = sequence.Slice(position);
            }

            //advance to the end of the last read frame
            this._receiveFromSocket.Reader.AdvanceTo(endPosition);
        }
    }
}
