﻿using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.IO.Pipelines;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Reflection;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.Wrappers;
using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.Collections;
using OpenSSL.Core.Error;

namespace OpenSSL.Core.SSL
{
    /* TODO
     * check for renegotiation
    */
    public partial class SocketConnection
    {
        internal class SslContextRefWrapper
        {
            internal SafeSslContextHandle SslContextHandle { get; set; }
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

        public bool SessionReused => !(this.SessionHandle is null) && this.SSLWrapper.SSL_session_reused(this.sslHandle) == 1;

        public SocketConnection ParentSession
        {
            set
            {
                if (!(value.SessionHandle is null))
                    this.SessionHandle = value.SessionHandle;
                else
                    throw new InvalidOperationException("No session set for parent connection");
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
                if (this.s_ClientCertificateCallback is null)
                    this.s_ClientCertificateCallback = this.ClientCertificateCallback;

                if (value is null)
                    this.SSLWrapper.SSL_CTX_set_client_cert_cb(this.SslContextWrapper.SslContextHandle, null);
                else
                    this.SSLWrapper.SSL_CTX_set_client_cert_cb(this.SslContextWrapper.SslContextHandle, this.s_ClientCertificateCallback);

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
            this.SSLWrapper.SSL_CTX_add_client_CA(this.SslContextWrapper.SslContextHandle, caCertificate.X509Wrapper.Handle);
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
            get => new X509Store(this.SSLWrapper.SSL_CTX_get_cert_store(this.SslContextWrapper.SslContextHandle));
            set => this.SSLWrapper.SSL_CTX_set_cert_store(this.SslContextWrapper.SslContextHandle, value.StoreWrapper.Handle);
        }

        /// <summary>
        /// Set.Get the certificate for this session.
        /// Can also be used to set the client certificate in client mode
        /// without using a client certificate callback
        /// </summary>
        public X509Certificate Certificate
        {
            get => new X509Certificate(this.SSLWrapper.SSL_CTX_get0_certificate(this.SslContextWrapper.SslContextHandle));
            set => this.SSLWrapper.SSL_CTX_use_certificate(this.SslContextWrapper.SslContextHandle, value.X509Wrapper.Handle);
        }

        /// <summary>
        /// Set/Gets the private key for this session
        /// </summary>
        public PrivateKey PrivateKey
        {
            get => PrivateKey.GetCorrectKey(this.SSLWrapper.SSL_CTX_get0_privatekey(this.SslContextWrapper.SslContextHandle));
            set => this.SSLWrapper.SSL_CTX_use_PrivateKey(this.SslContextWrapper.SslContextHandle, value.KeyWrapper.Handle);
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
            int read = this.CryptoWrapper.BIO_write(this.readHandle, readBuffer.Span.GetPinnableReference(), readBuffer.Length);

            if(read < readBuffer.Length)
                throw new ArgumentOutOfRangeException("Data not correctly written to BIO"); //TODO: undo operation / advance pipe?

            return read;
        }

        internal int ReadFromSsl(Memory<byte> writeBuffer)
        {
            int read = this.SSLWrapper.SSL_read(this.sslHandle, ref writeBuffer.Span.GetPinnableReference(), writeBuffer.Length);

            //TODO: manage renegotiate

            if (read > 0)
                return read;

            if (this.SSLWrapper.SSL_get_shutdown(this.sslHandle) == 2)
                throw new ShutdownException();

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
            if (this.s_VerifyCallback is null)
                this.s_VerifyCallback = this.VerifyCertificateCallback;

            if (remoteCertificateValidationHandler is null)
                this.SSLWrapper.SSL_CTX_set_verify(this.SslContextWrapper.SslContextHandle, 0, null);
            else
                this.SSLWrapper.SSL_CTX_set_verify(this.SslContextWrapper.SslContextHandle, (int)verifyMode, this.s_VerifyCallback);

            this.remoteCertificateValidationHandler = remoteCertificateValidationHandler;
        }

        private VerifyCertificateCallback s_VerifyCallback;
        private int VerifyCertificateCallback(int preVerify, IntPtr x509_store_ctx_ptr)
        {
            if (this.remoteCertificateValidationHandler is null)
                throw new InvalidOperationException("No verification callback has been defined");

            Type storeCtxType = DynamicTypeBuilder.GetConcreteOwnType<SafeX509StoreContextHandle>();
            ConstructorInfo ctor = storeCtxType.GetConstructor(new Type[] { typeof(IntPtr), typeof(bool), typeof(bool) });
            object newObj = ctor.Invoke(new object[] { x509_store_ctx_ptr, false, false });
            SafeX509StoreContextHandle x509_store_ctx = newObj as SafeX509StoreContextHandle;

            using (X509Certificate remoteCertificate = new X509Certificate(this.CryptoWrapper.X509_STORE_CTX_get_current_cert(x509_store_ctx)))
            {
                using (X509Store store = new X509Store(this.CryptoWrapper.X509_STORE_CTX_get0_store(x509_store_ctx)))
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

            Type sslType = DynamicTypeBuilder.GetConcreteOwnType<SafeSslHandle>();
            ConstructorInfo ctor = sslType.GetConstructor(new Type[] { typeof(IntPtr), typeof(bool), typeof(bool) });
            object newObj = ctor.Invoke(new object[] { sslPtr, false, false });
            SafeSslHandle ssl = newObj as SafeSslHandle;

            bool succes = false;
            x509Ptr = IntPtr.Zero;
            pkeyPtr = IntPtr.Zero;

            using (SafeStackHandle<SafeX509NameHandle> nameStackHandle = this.SSLWrapper.SSL_get_client_CA_list(ssl))
            {
                if (succes = this.clientCertificateCallbackHandler(
                    OpenSslReadOnlyCollection<X509Name>.CreateFromSafeHandle(nameStackHandle), 
                    out X509Certificate certificate, 
                    out PrivateKey privateKey))
                {
                    x509Ptr = certificate.X509Wrapper.Handle.DangerousGetHandle();
                    pkeyPtr = privateKey.KeyWrapper.Handle.DangerousGetHandle();
                }
            }

            return succes ? 1 : 0;
        }
        #endregion
    }
}
