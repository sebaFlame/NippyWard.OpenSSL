using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Reflection;
using System.Diagnostics;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Interop.Wrappers;
using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.Collections;
using OpenSSL.Core.Error;
using OpenSSL.Core.SSL.Pipelines;

namespace OpenSSL.Core.SSL
{
    /* TODO
     * check for renegotiation
    */
    public partial class SocketConnection
    {
        //TODO: add own reference count
        internal class SslContextRefWrapper : IDisposable
        {
            private bool IsServerContext;
            internal SafeSslContextHandle SslContextHandle { get; set; }

            internal SslContextRefWrapper(bool isServerContext = false)
            {
                this.IsServerContext = isServerContext;
            }

            public void Dispose()
            {
                if (this.IsServerContext)
                    return;

                this.SslContextHandle?.Dispose();
            }
        }

        #region native handles
        internal SslContextRefWrapper SslContextWrapper { get; set; }
        internal SafeSslSessionHandle SessionHandle { get; private set; }

        private SafeBioHandle readHandle;
        private SafeBioHandle writeHandle;
        private SafeSslHandle sslHandle;
        #endregion

        #region SSL fields
        private bool encryptionEnabled => this.IsAvailable(out SslState sslState) && sslState >= SslState.Established;

        private int _sslState;
        internal SslState SslState
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => (SslState)Thread.VolatileRead(ref this._sslState);
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

                using (SafeSslCipherHandle cipher = SSLWrapper.SSL_get_current_cipher(this.sslHandle))
                    return Native.PtrToStringAnsi(SSLWrapper.SSL_CIPHER_get_name(cipher), false);
            }
        }

        public SslProtocol Protocol
        {
            get
            {
                if (!this.encryptionEnabled)
                    throw new InvalidOperationException("Encryption has not been enabled yet");

                int versionNumber = SSLWrapper.SSL_version(this.sslHandle);
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

                return new X509Certificate(SSLWrapper.SSL_get_peer_certificate(this.sslHandle));
            }
        }

        public bool SessionReused => !(this.SessionHandle is null) && SSLWrapper.SSL_session_reused(this.sslHandle) == 1;

        private ClientCertificateCallbackHandler clientCertificateCallbackHandler;
        /// <summary>
        /// This sets the Client Certificate Callback
        /// </summary>
        public ClientCertificateCallbackHandler ClientCertificateCallbackHandler
        {
            get => this.clientCertificateCallbackHandler;
            set
            {
                if (this.s_ClientCertificateCallback is null)
                    this.s_ClientCertificateCallback = this.ClientCertificateCallback;

                if (value is null)
                    SSLWrapper.SSL_CTX_set_client_cert_cb(this.SslContextWrapper.SslContextHandle, null);
                else
                    SSLWrapper.SSL_CTX_set_client_cert_cb(this.SslContextWrapper.SslContextHandle, this.s_ClientCertificateCallback);

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
            SSLWrapper.SSL_CTX_add_client_CA(this.SslContextWrapper.SslContextHandle, caCertificate.X509Wrapper.Handle);
            if (addToChain)
                this.CertificateStore.AddCertificate(caCertificate);
        }

        private RemoteCertificateValidationHandler remoteCertificateValidationHandler;
        /// <summary>
        /// Set correct callback using <see cref="SetRemoteValidation(VerifyMode, RemoteCertificateValidationHandler)"/>
        /// </summary>
        public RemoteCertificateValidationHandler RemoteCertificateValidationHandler => this.remoteCertificateValidationHandler;

        public X509Store CertificateStore
        {
            get => new X509Store(SSLWrapper.SSL_CTX_get_cert_store(this.SslContextWrapper.SslContextHandle));
            set => SSLWrapper.SSL_CTX_set_cert_store(this.SslContextWrapper.SslContextHandle, value.StoreWrapper.Handle);
        }

        /// <summary>
        /// Set.Get the certificate for this session.
        /// Can also be used to set the client certificate in client mode
        /// without using a client certificate callback
        /// </summary>
        public X509Certificate Certificate
        {
            get => new X509Certificate(SSLWrapper.SSL_CTX_get0_certificate(this.SslContextWrapper.SslContextHandle));
            set => SSLWrapper.SSL_CTX_use_certificate(this.SslContextWrapper.SslContextHandle, value.X509Wrapper.Handle);
        }

        /// <summary>
        /// Set/Gets the private key for this session
        /// </summary>
        public PrivateKey PrivateKey
        {
            get => PrivateKey.GetCorrectKey(SSLWrapper.SSL_CTX_get0_privatekey(this.SslContextWrapper.SslContextHandle));
            set => SSLWrapper.SSL_CTX_use_PrivateKey(this.SslContextWrapper.SslContextHandle, value.KeyWrapper.Handle);
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
                if (position >= 3 || memory.Length >= 3)
                    lengthStart = memory.Span[3];
                if (position >= 4 || memory.Length >= 4)
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
            int read = CryptoWrapper.BIO_write(this.readHandle, readBuffer.Span.GetPinnableReference(), readBuffer.Length);

            if(read < readBuffer.Length)
                throw new ArgumentOutOfRangeException("Data not correctly written to BIO"); //TODO: undo operation / advance pipe?

            return read;
        }

        internal int ReadFromSsl(Memory<byte> writeBuffer, out int pending)
        {
            int read = SSLWrapper.SSL_read(this.sslHandle, ref writeBuffer.Span.GetPinnableReference(), writeBuffer.Length);
            pending = SSLWrapper.SSL_pending(this.sslHandle);

            //TODO: manage renegotiate

            //check if pending
            Debug.Assert(pending == 0);

            if (read > 0)
                return read;

            if (SSLWrapper.SSL_get_shutdown(this.sslHandle) == 2)
                throw new ShutdownException();

            //TODO: error handling incorrect
            int errorCode = SSLWrapper.SSL_get_error(this.sslHandle, read);
            SslError error = (SslError)errorCode;

            if (error == SslError.SSL_ERROR_WANT_READ)
                return 0;

            throw new InvalidOperationException($"SSL error: {error.ToString()}");
        }

        internal int WriteToSsl(ReadOnlyMemory<byte> readBuffer, int startPostion = 0)
        {
            ReadOnlySpan<byte> buffer;
            int written;

            if (startPostion == 0)
                buffer = readBuffer.Span;
            else
                buffer = readBuffer.Slice(startPostion).Span;

            written = SSLWrapper.SSL_write(this.sslHandle, buffer.GetPinnableReference(), buffer.Length);

            if (written > 0)
                return written;

            //TODO: error handling incorrect
            int errorCode = SSLWrapper.SSL_get_error(this.sslHandle, written);
            SslError error = (SslError)errorCode;

            if (error == SslError.SSL_ERROR_WANT_WRITE)
                return 0;

            throw new InvalidOperationException($"SSL error: {error.ToString()}");
        }

        internal int ReadFromSslBio(Memory<byte> writeBuffer, out int pending)
        {
            pending = 0;
            if (writeBuffer.IsEmpty)
                return (int)CryptoWrapper.BIO_ctrl_pending(this.writeHandle);

            try
            {
                return CryptoWrapper.BIO_read(this.writeHandle, ref writeBuffer.Span.GetPinnableReference(), writeBuffer.Length);
            }
            finally
            {
                pending = (int)CryptoWrapper.BIO_ctrl_pending(this.writeHandle);
            }
        }

        private ValueTask<FlushResult> WritePending()
        {
            uint waiting;
            int read, totalRead = 0;
            Memory<byte> writeBuffer;

            while ((waiting = CryptoWrapper.BIO_ctrl_pending(this.writeHandle)) > 0)
            {
                //get a buffer from the writer pool
                writeBuffer = this._sendToSocket.GetMemoryInternal(Native.SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER);

                //read what needs to be sent to the other party
                totalRead += (read = CryptoWrapper.BIO_read(this.writeHandle, ref writeBuffer.Span.GetPinnableReference(), writeBuffer.Length));

                //advance writer
                this._sendToSocket.AdvanceInternal(read);
            }

            // if (totalRead > 0)
            //     return this._sendToSocket.FlushAndAwaitSocketCompletionAsync(CancellationToken.None);
            // return new ValueTask<SocketFlushResult>(new SocketFlushResult(new FlushResult(false, true), 0, false, true));

            return this._sendToSocket.FlushAsyncInternal(CancellationToken.None);
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

            ValueTask<ReadResult> readResultTask = this._receiveFromSocket.ReadAsyncInternal(CancellationToken.None);
            if (!readResultTask.IsCompleted)
                readResult = await readResultTask.ConfigureAwait(false);
            else
                readResult = readResultTask.Result;

            sequence = readResult.Buffer;
            endPosition = sequence.Start;

            if (sequence.IsEmpty)
            {
                this._receiveFromSocket.AdvanceReaderInternal(endPosition);
                return;
            }

            while (ParseFrame(sequence, out position, out lengthWithHead, out frameType))
            {
                //if (frameType != FrameType.Handshake)
                //    return;

                readSequence = sequence.Slice(0, position);

                //write what was read from the other party
                if (readSequence.IsSingleSegment)
                    CryptoWrapper.BIO_write(this.readHandle, readSequence.First.Span.GetPinnableReference(), (int)readSequence.First.Length);
                else
                {
                    foreach (ReadOnlyMemory<byte> memory in readSequence)
                        CryptoWrapper.BIO_write(this.readHandle, memory.Span.GetPinnableReference(), memory.Length);
                }

                endPosition = readSequence.End;
                sequence = sequence.Slice(position);
            }

            //advance to the end of the last read frame
            this._receiveFromSocket.AdvanceReaderInternal(endPosition);
        }

        #region OpenSSL native callbacks
        /// <summary>
        /// Set the certificate verification callback
        /// </summary>
        /// <param name="verifyMode">Verify mode(s) OR'd together</param>
        /// <param name="remoteCertificateValidationHandler">The verification method to call. Can be null to reset</param>
        public void SetRemoteValidation(VerifyMode verifyMode, RemoteCertificateValidationHandler remoteCertificateValidationHandler)
        {
            if (this.s_VerifyCallback is null)
                this.s_VerifyCallback = this.VerifyCertificateCallback;

            if (remoteCertificateValidationHandler is null)
                SSLWrapper.SSL_CTX_set_verify(this.SslContextWrapper.SslContextHandle, 0, null);
            else
                SSLWrapper.SSL_CTX_set_verify(this.SslContextWrapper.SslContextHandle, (int)verifyMode, this.s_VerifyCallback);

            this.remoteCertificateValidationHandler = remoteCertificateValidationHandler;
        }

        private VerifyCertificateCallback s_VerifyCallback;
        private int VerifyCertificateCallback(int preVerify, IntPtr x509_store_ctx_ptr)
        {
            if (this.remoteCertificateValidationHandler is null)
                throw new InvalidOperationException("No verification callback has been defined");

            Type storeCtxType = null;
            ConstructorInfo ctor = storeCtxType.GetConstructor(new Type[] { typeof(IntPtr), typeof(bool), typeof(bool) });
            object newObj = ctor.Invoke(new object[] { x509_store_ctx_ptr, false, false });
            SafeX509StoreContextHandle x509_store_ctx = newObj as SafeX509StoreContextHandle;

            using (X509Certificate remoteCertificate = new X509Certificate(CryptoWrapper.X509_STORE_CTX_get_current_cert(x509_store_ctx)))
            {
                using (X509Store store = new X509Store(CryptoWrapper.X509_STORE_CTX_get0_store(x509_store_ctx)))
                {
                    using (OpenSslReadOnlyCollection<X509Certificate> certList = store.GetCertificates())
                    {
                        return this.remoteCertificateValidationHandler(preVerify == 1, remoteCertificate, certList) ? 1 : 0;
                    }
                }
            }
        }

        private ClientCertificateCallback s_ClientCertificateCallback;
        private int ClientCertificateCallback(IntPtr sslPtr, out IntPtr x509Ptr, out IntPtr pkeyPtr)
        {
            if (this.clientCertificateCallbackHandler is null)
                throw new InvalidOperationException("No client certificate callback has been defined");

            Type sslType = null;
            ConstructorInfo ctor = sslType.GetConstructor(new Type[] { typeof(IntPtr), typeof(bool), typeof(bool) });
            object newObj = ctor.Invoke(new object[] { sslPtr, false, false });
            SafeSslHandle ssl = newObj as SafeSslHandle;

            bool succes = false;
            x509Ptr = IntPtr.Zero;
            pkeyPtr = IntPtr.Zero;

            SafeStackHandle<SafeX509NameHandle> nameStackHandle = SSLWrapper.SSL_get_client_CA_list(ssl);
            using(OpenSslReadOnlyCollection<X509Name> nameList = OpenSslReadOnlyCollection<X509Name>.CreateFromSafeHandle(nameStackHandle))
            {
                if (succes = this.clientCertificateCallbackHandler(
                    nameList, 
                    out X509Certificate certificate, 
                    out PrivateKey privateKey))
                {
                    certificate.X509Wrapper.Handle.AddRef(); //add reference, so SSL doesn't free our objects
                    x509Ptr = certificate.X509Wrapper.Handle.DangerousGetHandle();
                    privateKey.KeyWrapper.Handle.AddRef(); //add reference, so SSL doesn't free our objects
                    pkeyPtr = privateKey.KeyWrapper.Handle.DangerousGetHandle();
                }
            }

            return succes ? 1 : 0;
        }
        #endregion
    }
}
