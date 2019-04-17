using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.IO.Pipelines;
using System.Buffers;
using System.Runtime.CompilerServices;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;

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
        private bool encryptionEnabled => this.IsAvailable(out SslState sslState) && sslState == SslState.Established;

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

        public X509Certificate RemoteCertificate
        {
            get
            {
                if (!this.IsAvailable(out SslState sslState))
                    throw new InvalidOperationException(sslState == SslState.None ? "Encryption has not been enabled yet" : $"Current connection state: {sslState}");

                return new X509Certificate(this.SSLWrapper.SSL_get_peer_certificate(this.sslHandle));
            }
        }

        private ClientCertificateCallbackHandler clientCertificateCallbackHandler;
        /// <summary>
        /// This sets the Client Certificate Callback
        /// </summary>
        public ClientCertificateCallbackHandler ClientCertificateCallbackHandler
        {
            get => this.clientCertificateCallbackHandler;
            set
            {
                if (this.clientCertificateCallbackHandler is null)
                    this.SSLWrapper.SSL_CTX_set_client_cert_cb(this.sslContextHandle, this.ClientCertificateCallback);
                else if (value is null)
                    this.SSLWrapper.SSL_CTX_set_client_cert_cb(this.sslContextHandle, null);

                this.clientCertificateCallbackHandler = value;
            }
        }

        /// <summary>
        /// Add a CA certificate to verify a client certificate in server mode
        /// Using this method you can use internal certificate verification
        /// This sends a list of valid CA to the client for correct client certificate selection
        /// </summary>
        /// <param name="caCertificate">The certificate to add</param>
        /// <param name="addToChain">Add the certificate to the verification chain if it's not available in the current <see cref="CertificateStore"/></param>
        public void AddClientCertificateCA(X509Certificate caCertificate, bool addToChain = true)
        {
            this.SSLWrapper.SSL_CTX_add_client_CA(this.sslContextHandle, caCertificate.X509Handle);
            if (addToChain)
                this.SSLWrapper.SSL_CTX_add_extra_chain_cert(this.sslContextHandle, caCertificate.X509Handle);
        }

        private RemoteCertificateValidationHandler remoteCertificateValidationHandler;
        /// <summary>
        /// Set correct callback using <see cref="SetRemoteValidation(VerifyMode, RemoteCertificateValidationHandler)"/>
        /// </summary>
        public RemoteCertificateValidationHandler RemoteCertificateValidationHandler => this.remoteCertificateValidationHandler;

        public X509Store CertificateStore
        {
            get => new X509Store(this.SSLWrapper.SSL_CTX_get_cert_store(this.sslContextHandle));
            set => this.SSLWrapper.SSL_CTX_set_cert_store(this.sslContextHandle, value.StoreHandle);
        }

        /// <summary>
        /// Set.Get the certificate for this session.
        /// Can also be used to set the client certificate
        /// without using a client certificate callback
        /// </summary>
        public X509Certificate Certificate
        {
            get => new X509Certificate(this.SSLWrapper.SSL_CTX_get0_certificate(this.sslContextHandle));
            set => this.SSLWrapper.SSL_CTX_use_certificate(this.sslContextHandle, value.X509Handle);
        }

        /// <summary>
        /// Set/Gets the private key for this session
        /// </summary>
        public PrivateKey PrivateKey
        {
            get => PrivateKey.GetCorrectKey(this.SSLWrapper.SSL_CTX_get0_privatekey(this.sslContextHandle));
            set => this.SSLWrapper.SSL_CTX_use_PrivateKey(this.sslContextHandle, value.KeyHandle);
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

        #region OpenSSL callback options
        /// <summary>
        /// Set the certificate verification callback
        /// </summary>
        /// <param name="verifyMode">Verify mode(s) OR'd together</param>
        /// <param name="remoteCertificateValidationHandler">The verification method to call. Can be null to reset</param>
        public void SetRemoteValidation(VerifyMode verifyMode, RemoteCertificateValidationHandler remoteCertificateValidationHandler)
        {
            if (this.remoteCertificateValidationHandler is null)
                this.SSLWrapper.SSL_CTX_set_verify(this.sslContextHandle, (int)verifyMode, this.VerifyCertificateCallback);
            else if (remoteCertificateValidationHandler is null)
                this.SSLWrapper.SSL_CTX_set_verify(this.sslContextHandle, 0, null);

            this.remoteCertificateValidationHandler = remoteCertificateValidationHandler;
        }

        private int VerifyCertificateCallback(int preVerify, SafeX509StoreContextHandle x509_store_ctx)
        {
            if (this.remoteCertificateValidationHandler is null)
                throw new InvalidOperationException("No verification callback has been defined");

            SafeX509CertificateHandle certHandle = this.CryptoWrapper.X509_STORE_CTX_get_current_cert(x509_store_ctx);
            using (SafeX509StoreHandle store = this.CryptoWrapper.X509_STORE_CTX_get0_store(x509_store_ctx))
            {
                using (X509CertificateList certList = new X509CertificateList(store))
                {
                    using (X509Certificate remoteCertificate = new X509Certificate(certHandle))
                    {
                        return this.remoteCertificateValidationHandler((VerifyResult)preVerify, remoteCertificate, certList) ? 1 : 0;
                    }
                }
            }
        }

        private int ClientCertificateCallback(SafeSslHandle ssl, out SafeX509CertificateHandle x509, out SafeKeyHandle pkey)
        {
            if (this.clientCertificateCallbackHandler is null)
                throw new InvalidOperationException("No client certificate callback has been defined");

            bool succes = false;
            x509 = null;
            pkey = null;

            using (SafeStackHandle<SafeX509NameHandle> nameStackHandle = this.SSLWrapper.SSL_get_client_CA_list(ssl))
            {
                X509Name[] validCA = new X509Name[nameStackHandle.Count];
                for (int i = 0; i < nameStackHandle.Count; i++)
                    validCA[i] = new X509Name(nameStackHandle[i]);

                if (succes = this.clientCertificateCallbackHandler(validCA, out X509Certificate certificate, out PrivateKey privateKey))
                {
                    x509 = certificate.X509Handle;
                    pkey = privateKey.KeyHandle;
                }
            }

            return succes ? 1 : 0;
        }
        #endregion
    }
}
