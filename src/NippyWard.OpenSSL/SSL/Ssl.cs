using System;
using System.Collections.Generic;
using System.Threading;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Diagnostics;

using NippyWard.OpenSSL.Interop;
using NippyWard.OpenSSL.Interop.SafeHandles;
using NippyWard.OpenSSL.Interop.SafeHandles.SSL;
using NippyWard.OpenSSL.Interop.Wrappers;
using NippyWard.OpenSSL.X509;
using NippyWard.OpenSSL.Keys;
using NippyWard.OpenSSL.Error;

namespace NippyWard.OpenSSL.SSL
{
    public class Ssl : OpenSslBase, IDisposable
    {
        public ISet<string> SupportedCiphers
            => SslContext.GenerateSupportedCiphers(this._sslContext._sslContextHandle);

        public string Cipher
        {
            get
            {
                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                lock(this._lock)
                {
                    using (SafeSslCipherHandle cipher = SSLWrapper.SSL_get_current_cipher(this._sslHandle))
                    {
                        return Native.PtrToStringAnsi(SSLWrapper.SSL_CIPHER_get_name(cipher), false);
                    }
                }
            }
        }

        public SslProtocol Protocol
        {
            get
            {
                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                int versionNumber = 0;
                lock (this._lock)
                {
                    versionNumber = SSLWrapper.SSL_version(this._sslHandle);
                }
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
                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                lock(this._lock)
                {
                    return new X509Certificate(SSLWrapper.SSL_get_peer_certificate(this._sslHandle));
                }
            }
        }

        public bool IsSessionReused
        {
            get
            {
                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                lock(this._lock)
                {
                    return SSLWrapper.SSL_session_reused(this._sslHandle) == 1;
                }
            }
        }

        public X509Store CertificateStore
        {
            get
            {
                lock (this._lock)
                {
                    return new X509Store(SSLWrapper.SSL_CTX_get_cert_store(this._sslContext._sslContextHandle));
                }
            }
        }

        /// <summary>
        /// Set.Get the certificate for this session.
        /// Can also be used to set the client certificate in client mode
        /// without using a client certificate callback
        /// </summary>
        public X509Certificate Certificate
        {
            get
            {
                lock(this._lock)
                {
                    return new X509Certificate(SSLWrapper.SSL_CTX_get0_certificate(this._sslContext._sslContextHandle));
                }
            }
        }

        /// <summary>
        /// Set/Gets the private key for this session
        /// </summary>
        public PrivateKey PrivateKey
        {
            get
            {
                lock(this._lock)
                {
                    return PrivateKey.GetCorrectKey(SSLWrapper.SSL_CTX_get0_privatekey(this._sslContext._sslContextHandle));
                }
            }
        }

        /// <summary>
        /// Gets the session for the current context
        /// </summary>
        public SslSession? Session
        {
            get
            {
                //server side does not use a session
                if (this.IsServer)
                {
                    return null;
                }

                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                if(this._sslContext._sessionHandle is null)
                {
                    throw new NullReferenceException("Session has not been initialized yet");
                }

                lock(this._lock)
                {
                    return new SslSession(this._sslContext._sessionHandle);
                }
            }
        }

        /// <summary>
        /// Returns the OK status of the (remote) certificate validation when correctly validated or throws an exception.
        /// </summary>
        public VerifyResult CertificateValidationResult
        {
            get
            {
                VerifyResult verifyResult;
                lock (this._lock)
                {
                    if ((verifyResult = (VerifyResult)SSLWrapper.SSL_get_verify_result(this._sslHandle)) > VerifyResult.X509_V_OK)
                    {
                        throw new OpenSslException
                        (
                            new VerifyError(verifyResult)
                        );
                    }
                    return verifyResult;
                }
            }
        }

        public bool IsServer => this._isServer;
        /// <summary>
        /// Reusable SSL context. Eg for session reuse between multiple clients on a server.
        /// </summary>
        public SslContext SslContext => this._sslContext;

        public const SslStrength _DefaultSslStrength = SslStrength.Level2;
        public const SslProtocol _DefaultSslProtocol = SslProtocol.Tls12 | SslProtocol.Tls13;

        #region native handles
        private readonly SafeBioHandle _internalBio;
        private readonly SafeBioHandle _netBio;
        private readonly SafeSslHandle _sslHandle;
        private readonly SafeBioHandle _sslBio;
        #endregion

        private bool _handshakeCompleted;
        private bool _inRenegotiation;
        private readonly bool _isServer;
        private readonly SslContext _sslContext;

        //a single lock to facilitate SSL state changes
        private readonly object _lock;

        //bss_bio.c
        private const int _MaxPairBufferSize = 17 * 1024;

        public static Ssl CreateClientSsl
        (
            SslOptions sslOptions
        )
            => CreateClientSsl
            (
                sslOptions.SslStrength,
                sslOptions.SslProtocol,
                sslOptions.CertificateStore,
                sslOptions.Certificate,
                sslOptions.PrivateKey,
                sslOptions.ClientCertificateCallbackHandler,
                sslOptions.RemoteCertificateValidationHandler,
                sslOptions.PreviousSession,
                sslOptions.Ciphers
            );

        public static Ssl CreateClientSsl
        (
            SslStrength? sslStrength = null,
            SslProtocol? sslProtocol = null,
            X509Store? certificateStore = null,
            X509Certificate? certificate = null,
            PrivateKey? privateKey = null,
            ClientCertificateCallbackHandler? clientCertificateCallbackHandler = null,
            RemoteCertificateValidationHandler? remoteCertificateValidationHandler = null,
            SslSession? previousSession = null,
            IEnumerable<string>? ciphers = null
        )
        {
            bool isServer = false;
            return new Ssl
            (
                isServer,
                SslContext.CreateSslContext
                (
                    sslStrength: sslStrength ?? _DefaultSslStrength,
                    sslProtocol: sslProtocol ?? _DefaultSslProtocol,
                    certificateStore: certificateStore,
                    certificate: certificate,
                    privateKey: privateKey,
                    clientCertificateCallbackHandler: clientCertificateCallbackHandler,
                    remoteCertificateValidationHandler: remoteCertificateValidationHandler,
                    ciphers: ciphers,
                    isServer
                ),
                previousSession
            );
        }

        public static Ssl CreateServerSsl
        (
            SslOptions sslOptions
        )
            => CreateServerSsl
            (
                sslOptions.SslStrength,
                sslOptions.SslProtocol,
                sslOptions.CertificateStore,
                sslOptions.Certificate,
                sslOptions.PrivateKey,
                sslOptions.ClientCertificateCallbackHandler,
                sslOptions.RemoteCertificateValidationHandler,
                sslOptions.PreviousSession,
                sslOptions.Ciphers
            );

        public static Ssl CreateServerSsl
        (
            SslStrength? sslStrength = null,
            SslProtocol? sslProtocol = null,
            X509Store? certificateStore = null,
            X509Certificate? certificate = null,
            PrivateKey? privateKey = null,
            ClientCertificateCallbackHandler? clientCertificateCallbackHandler = null,
            RemoteCertificateValidationHandler? remoteCertificateValidationHandler = null,
            SslSession? previousSession = null,
            IEnumerable<string>? ciphers = null
        )
        {
            bool isServer = true;
            return new Ssl
            (
                isServer,
                SslContext.CreateSslContext
                (
                    sslStrength: sslStrength ?? _DefaultSslStrength,
                    sslProtocol: sslProtocol ?? _DefaultSslProtocol,
                    certificateStore: certificateStore,
                    certificate: certificate,
                    privateKey: privateKey,
                    clientCertificateCallbackHandler: clientCertificateCallbackHandler,
                    remoteCertificateValidationHandler: remoteCertificateValidationHandler,
                    ciphers: ciphers,
                    isServer
                ),
                previousSession
            );
        }

        /// <summary>
        /// This wraps the old SslContext to use for session reuse.
        /// </summary>
        /// <param name="previousServerContext"></param>
        /// <returns></returns>
        public static Ssl CreateServerSsl
        (
            SslContext previousServerContext
        )
        {
            return new Ssl
            (
                true,
                previousServerContext
            );
        }

        private Ssl
        (
            bool isServer,
            SslContext sslContext,
            SslSession? previousSession = null
        )
        {
            this._lock = new object();

            //add a (managed) reference, so the object can be reused
            bool success = true;
            sslContext._sslContextHandle.DangerousAddRef(ref success);

            //DangerousAddRef either throws an exception
            //or returns success
            if (!success)
            {
                throw new InvalidOperationException("Can not happen???");
            }

            SafeBioHandle? internalBio = null, netBio = null, sslBio = null;
            SafeSslHandle? sslHandle = null;
            try
            {
                sslHandle = SSLWrapper.SSL_new(sslContext._sslContextHandle);

                //set correct connection endpoint options
                if (isServer)
                {
                    SSLWrapper.SSL_set_accept_state(sslHandle);

                    //fix for TLS1.3 server session send during handshake (510 bytes)
                    //should not be an issue anymore, but keep it for future reference
                    //SSLWrapper.SSL_set_num_tickets(sslHandle, 0);
                }
                else
                {
                    SSLWrapper.SSL_set_connect_state(sslHandle);
                }

                //enable session reuse
                if (previousSession is not null)
                {
                    SSLWrapper.SSL_set_session(sslHandle, previousSession._Handle);
                }

                CryptoWrapper.BIO_new_bio_pair(out internalBio, 0, out netBio, 0);
                SSLWrapper.SSL_set_bio(sslHandle, internalBio, internalBio);

                sslBio = CryptoWrapper.BIO_new(SSLWrapper.BIO_f_ssl());
                CryptoWrapper.BIO_ctrl(sslBio, 109, 0, sslHandle.DangerousGetHandle()); //109 == BIO_C_SET_SSL
            }
            catch (Exception)
            {
                internalBio?.Dispose();
                netBio?.Dispose();
                sslHandle?.Dispose();
                sslBio?.Dispose();

                throw;
            }

            //assign relevant fields
            this._sslContext = sslContext;
            this._internalBio = internalBio;
            this._netBio = netBio;
            this._sslHandle = sslHandle;
            this._sslBio = sslBio;

            //add references for correct disposal
            this._internalBio.AddReference();
            this._netBio.AddReference();
            this._sslBio.AddReference();

            this._handshakeCompleted = false;
            this._isServer = isServer;
        }

        ~Ssl()
        {
            this.Dispose(false);
        }

        /// <summary>
        /// Initialize or continue an SSL handshake
        /// </summary>
        /// <param name="state">contains the action needed to complete the handshake</param>
        /// <returns>true when the handshake has completed</returns>
        public bool DoHandshake
        (
            out SslState state
        )
        {
            int ret_code;

            lock (this._lock)
            {
                ret_code = SSLWrapper.SSL_do_handshake(this._sslHandle);

                return this.VerifyDoHandshake(ret_code, out state);
            }
        }

        private bool VerifyDoHandshake(int ret_code, out SslState state)
        {
            Debug.Assert(Monitor.IsEntered(this._lock), "Lock not entered.");

            //get next action from OpenSSL wrapper
            if (ret_code == 1)
            {
                //reset the SSL_ERROR_WANT_READ after the handshake has finished
                if (SSLWrapper.SSL_is_init_finished(this._sslHandle) == 1)
                {
                    CryptoWrapper.BIO_ctrl_reset_read_request(this._netBio);
                }

                state = this.VerifyState();

                if (state != SslState.NONE)
                {
                    return false;
                }

                this._handshakeCompleted = true;
                return true;
            }
            else
            {
                state = this.VerifyError(ret_code);
                return false;
            }
        }

        /// <summary>
        /// Initialize or continue an SSL shutdown. Continueing a shutdown with a read/write is not mandatory!
        /// </summary>
        /// <param name="state">Contains the action needed to complete the handshake. This is not mandatory.</param>
        /// <returns>true when the shutdown has completed</returns>
        public bool DoShutdown
        (
            out SslState state
        )
        {
            int ret_code;

            try
            {
                lock (this._lock)
                {
                    ret_code = SSLWrapper.SSL_shutdown(this._sslHandle);

                    //initialize (or continue) a shutdown
                    if (ret_code == 1)
                    {
                        state = this.VerifyState();
                        return state == SslState.SHUTDOWN;
                    }
                    else if (ret_code == 0)
                    {
                        //force check bio states
                        state = this.VerifyState();
                        return false;
                    }
                    else
                    {
                        state = this.VerifyError(ret_code);
                        return false;
                    }
                }
            }
            finally
            {
                //set the ssl context as "handshake not completed"
                this._handshakeCompleted = false;
            }
        }

        /// <summary>
        /// Force a new handshake resuming the existing session
        /// </summary>
        public bool DoRenegotiate(out SslState sslState)
        {
            ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

            bool ret = false;

            //ensure the renegotiate/handshake function get executed together
            //so no read/write gets inbetween
            lock (this._lock)
            {
                if(this._inRenegotiation == false)
                {
                    //these functions do not change state and rely on SSL_do_handshake instead -> no lock
                    if (this.Protocol == SslProtocol.Tls13)
                    {
                        //requests an update from peer when using 1 (SSL_KEY_UPDATE_REQUESTED)
                        SSLWrapper.SSL_key_update(this._sslHandle, 1);
                    }
                    else
                    {
                        SSLWrapper.SSL_renegotiate_abbreviated(this._sslHandle);
                    }
                }

                this._inRenegotiation = true;

                ret = this.DoHandshake(out sslState);
            }

            if (ret)
            {
                this._inRenegotiation = false;
            }

            return ret;
        }

        /// <summary>
        /// Read encrypted data from <paramref name="readableBuffer"/> and decrypt into <paramref name="writableBuffer"/>
        /// </summary>
        /// <param name="readableBuffer">Encrypted buffer</param>
        /// <param name="writableBuffer">The buffer to decrypt to</param>
        /// <param name="totalRead">Total bytes read from the encrypted buffer</param>
        /// <param name="totalWritten">Total bytes written to decrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslStateExtensions.WantsRead(SslState)"/> or <see cref="SslStateExtensions.WantsWrite(SslState)"/> when the SSL connection needs data.</returns>
        /// <exception cref="OpenSslException"></exception>
        public SslState ReadSsl
        (
            ReadOnlySpan<byte> readableBuffer,
            Span<byte> writableBuffer,
            out int totalRead,
            out int totalWritten
        )
        {
            int readIndex = 0, writeIndex = 0;
            int written, read = 0;
            SslState sslState;

            ReadOnlySpan<byte> readBuf;
            Span<byte> writeBuf;

            readBuf = SliceReadableSpan
            (
                readableBuffer,
                readIndex,
                _MaxPairBufferSize
            );

            do
            {
                //keep both the BIO and the SSL inside the lock, so we don't get (unexpected) concurrency issues
                //during SSL state changes
                lock (this._lock)
                {
                    //allow to continue from previous read operation
                    while (!readBuf.IsEmpty 
                        && CryptoWrapper.BIO_ctrl_pending(this._sslBio) < _MaxPairBufferSize)
                    {
                        //write a (possible) packet of encrypted data to the BIO
                        written = CryptoWrapper.BIO_write(this._netBio, in MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        if (written <= 0)
                        {
                            totalRead = readIndex;
                            totalWritten = writeIndex;
                            sslState = this.VerifyError(written);

                            if (sslState.IsDataAvailable())
                            {
                                break;
                            }

                            return sslState;
                        }
                        else
                        {
                            //increment read index
                            readIndex += written;

                            //create new buffer
                            readBuf = SliceReadableSpan
                            (
                                readableBuffer,
                                readIndex,
                                _MaxPairBufferSize
                            );
                        }
                    }

                    writeBuf = SliceSpan
                    (
                        writableBuffer,
                        writeIndex,
                        _MaxPairBufferSize
                    );

                    //then read the (unencrypted) buffer into the bufferwriter
                    sslState = this.ReadUnencryptedIntoBuffer
                    (
                        writeBuf,
                        out read
                    );
                }

                //increase write index
                writeIndex += read;

                if (sslState > 0
                    && !sslState.WantsRead())
                {
                    break;
                }
            } while (!readBuf.IsEmpty);

            totalRead = readIndex;
            totalWritten = writeIndex;
            return sslState;
        }

        private SslState ReadUnencryptedIntoBuffer
        (
            Span<byte> writeableBuffer,
            out int totalWritten
        )
        {
            Debug.Assert(Monitor.IsEntered(this._lock), "Lock not entered.");

            int read = 0;
            totalWritten = 0;

            //writeableBuffer CAN be empty, allow to force a "flush" of non-application data

            Span<byte> buf = writeableBuffer;

            while (CryptoWrapper.BIO_ctrl_pending(this._sslBio) > 0
                && !buf.IsEmpty)
            {
                read = CryptoWrapper.BIO_read(this._sslBio, ref MemoryMarshal.GetReference<byte>(buf), buf.Length);

                if(read <= 0)
                {
                    SslState sslState =  this.VerifyError(read);
                    if(sslState == SslState.READ_DATA_AVAILABLE)
                    {
                        continue;
                    }
                    return sslState;
                }
                else
                {
                    totalWritten += read;
                }

                buf = writeableBuffer.Slice(totalWritten);
            }

            return this.VerifyState();
        }

        /// <summary>
        /// Read encrypted data from <paramref name="span"/> and decrypt into <paramref name="bufferWriter"/>
        /// </summary>
        /// <param name="span">Encrypted buffer</param>
        /// <param name="bufferWriter">The buffer to decrypt to</param>
        /// <param name="totalRead">Total bytes read from the encrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslStateExtensions.WantsRead(SslState)"/> or <see cref="SslStateExtensions.WantsWrite(SslState)"/> when the SSL connection needs data.</returns>
        public SslState ReadSsl
        (
            ReadOnlySpan<byte> readableBuffer,
            IBufferWriter<byte> bufferWriter,
            out int totalRead
        )
        {
            int readIndex = 0;
            int written;
            SslState sslState;
            ReadOnlySpan<byte> readBuf;

            readBuf = SliceReadableSpan
            (
                readableBuffer,
                readIndex,
                _MaxPairBufferSize
            );

            do
            {
                lock (this._lock)
                {
                    //allow to continue from previous read operation
                    while (!readBuf.IsEmpty
                        && CryptoWrapper.BIO_ctrl_pending(this._sslBio) < _MaxPairBufferSize)
                    {
                        //write a (possible) packet of encrypted data to the BIO
                        written = CryptoWrapper.BIO_write(this._netBio, in MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        if (written <= 0)
                        {
                            totalRead = readIndex;
                            sslState = this.VerifyError(written);

                            if (sslState.IsDataAvailable())
                            {
                                break;
                            }

                            return sslState;
                        }
                        else
                        {
                            //increment read index
                            readIndex += written;
                        }

                        readBuf = SliceReadableSpan
                        (
                            readableBuffer,
                            readIndex,
                            _MaxPairBufferSize
                        );
                    }

                    //allow for atleast a flush
                    //then read the (unencrypted) buffer into the bufferwriter
                    sslState = this.ReadUnencryptedIntoBufferWriter
                    (
                        bufferWriter
                    );
                }

                if (sslState > 0
                    && !sslState.WantsRead())
                {
                    break;
                }
            } while (!readBuf.IsEmpty);

            totalRead = readIndex;
            return sslState;
        }

        /// <summary>
        /// Read encrypted data from <paramref name="sequence"/> and decrypt into <paramref name="bufferWriter"/>
        /// </summary>
        /// <param name="sequence">Encrypted buffer</param>
        /// <param name="bufferWriter">The buffer to decrypt to</param>
        /// <param name="totalRead">Total bytes read from the encrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslStateExtensions.WantsRead(SslState)"/> or <see cref="SslStateExtensions.WantsWrite(SslState)"/> when the SSL connection needs data.</returns>
        public SslState ReadSsl
        (
            in ReadOnlySequence<byte> sequence,
            IBufferWriter<byte> bufferWriter,
            out SequencePosition totalRead
        )
        {
            totalRead = sequence.Start;

            SslState sslState = SslState.NONE;
            int read;

            if (sequence.IsSingleSegment)
            {
                sslState = this.ReadSsl(sequence.FirstSpan, bufferWriter, out read);
                totalRead = sequence.GetPosition(read);
                return sslState;
            }

            int written, totalIndex = 0;
            ReadOnlySpan<byte> span;
            ReadOnlySequence<byte> s;

            s = SliceReadOnlySequence
            (
                in sequence,
                sequence.Start,
                _MaxPairBufferSize
            );

            do
            {
                ReadOnlySequence<byte>.Enumerator memoryEnumerator = s.GetEnumerator();

                lock (this._lock)
                {
                    while (memoryEnumerator.MoveNext()
                        && CryptoWrapper.BIO_ctrl_pending(this._sslBio) < _MaxPairBufferSize)
                    {
                        if (memoryEnumerator.Current.IsEmpty)
                        {
                            continue;
                        }

                        //TODO: what if span.Length > _MaxPairBufferSize
                        span = memoryEnumerator.Current.Span;

                        //write a (possible) packet of encrypted data to the BIO
                        written = CryptoWrapper.BIO_write(this._netBio, in MemoryMarshal.GetReference<byte>(span), span.Length);

                        if (written <= 0)
                        {
                            sslState = this.VerifyError(written);

                            if (sslState.IsDataAvailable())
                            {
                                break;
                            }

                            totalRead = sequence.GetPosition(totalIndex);
                            return sslState;
                        }
                        else
                        {
                            //increment read index
                            totalIndex += written;
                        }
                    }

                    //then read the (unencrypted) buffer into the bufferwriter
                    sslState = this.ReadUnencryptedIntoBufferWriter
                    (
                        bufferWriter
                    );
                }

                //get the position which has been read to
                totalRead = sequence.GetPosition(totalIndex);

                if (sslState > 0
                    && !sslState.WantsRead())
                {
                    break;
                }

                s = SliceReadOnlySequence
                (
                    in sequence,
                    totalRead,
                    _MaxPairBufferSize
                );
            } while (!s.IsEmpty);

            return sslState;
        }

        private SslState ReadUnencryptedIntoBufferWriter
        (
            IBufferWriter<byte> bufferWriter
        )
        {
            Debug.Assert(Monitor.IsEntered(this._lock), "Lock not entered.");

            int read;
            Span<byte> writeBuffer;

            while (CryptoWrapper.BIO_ctrl_pending(this._sslBio) > 0)
            {
                //get a buffer from the IBufferWriter (of unkown length - use 16384 as default)
                writeBuffer = bufferWriter.GetSpan(1);

                //and write decrypted data to the buffer received from IBufferWriter
                read = CryptoWrapper.BIO_read(this._sslBio, ref MemoryMarshal.GetReference<byte>(writeBuffer), writeBuffer.Length);

                if (read <= 0)
                {
                    SslState sslState = this.VerifyError(read);
                    if (sslState == SslState.READ_DATA_AVAILABLE)
                    {
                        continue;
                    }
                    return sslState;
                }

                //advance buffer writer with the amount read
                bufferWriter.Advance(read);
            }

            return this.VerifyState();
        }

        /// <summary>
        /// Write unencrypted data from <paramref name="readableBuffer"/> and encrypt into <paramref name="writableBuffer"/>
        /// </summary>
        /// <param name="readableBuffer">Unencrypted buffer</param>
        /// <param name="writableBuffer">The buffer to ecnrypt to</param>
        /// <param name="totalRead">Total bytes read from the unencrypted buffer</param>
        /// <param name="totalWritten">Total bytes written into the encrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslStateExtensions.WantsRead(SslState)"/> or <see cref="SslStateExtensions.WantsWrite(SslState)"/> when the SSL connection needs data.</returns>
        public SslState WriteSsl
        (
            ReadOnlySpan<byte> readableBuffer,
            Span<byte> writableBuffer,
            out int totalRead,
            out int totalWritten
        )
        {
            int readIndex = 0, writeIndex = 0;
            int written, read = 0;
            SslState sslState = SslState.NONE;

            ReadOnlySpan<byte> readBuf;
            Span<byte> writeBuf;

            readBuf = SliceReadableSpan
            (
                readableBuffer,
                readIndex,
                _MaxPairBufferSize
            );

            do
            {
                lock (this._lock)
                {
                    //allow to continue from previous write operation
                    while (!readBuf.IsEmpty)
                    {
                        //write unencrypted data into ssl
                        written = CryptoWrapper.BIO_write(this._sslBio, in MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        if (written <= 0)
                        {
                            totalRead = readIndex;
                            totalWritten = writeIndex;
                            sslState = this.VerifyError(written);

                            if (sslState.WantsWrite())
                            {
                                break;
                            }

                            return sslState;
                        }
                        else
                        {
                            readIndex += written;
                        }

                        readBuf = SliceReadableSpan
                        (
                            readableBuffer,
                            readIndex,
                            _MaxPairBufferSize
                        );
                    }

                    writeBuf = SliceSpan
                    (
                        writableBuffer,
                        writeIndex,
                        _MaxPairBufferSize
                    );

                    //read encrypted data
                    sslState = this.ReadEncryptedIntoBuffer
                    (
                        writeBuf,
                        out read
                    );
                }

                //increase write index
                writeIndex += read;

                //no more data can be written
                if (sslState > 0)
                {
                    break;
                }

            } while (!readBuf.IsEmpty);

            totalRead = readIndex;
            totalWritten = writeIndex;
            return sslState;
        }

        private SslState ReadEncryptedIntoBuffer
        (
            Span<byte> writableBuffer,
            out int totalWritten
        )
        {
            Debug.Assert(Monitor.IsEntered(this._lock), "Lock not entered.");

            int written;
            totalWritten = 0;
            Span<byte> buf = writableBuffer;

            while (CryptoWrapper.BIO_ctrl_pending(this._netBio) > 0
                && !buf.IsEmpty)
            { 
                //and write encrypted data to the buffer received from IBufferWriter
                written = CryptoWrapper.BIO_read(this._netBio, ref MemoryMarshal.GetReference<byte>(buf), buf.Length);

                if (written <= 0)
                {
                    SslState sslState = this.VerifyError(written);

                    if(sslState.WantsWrite())
                    {
                        continue;
                    }

                    return sslState;
                }
                else
                {
                    totalWritten += written;
                }

                buf = writableBuffer.Slice(totalWritten);
            }

            return this.VerifyState();
        }

        /// <summary>
        /// Write unencrypted data from <paramref name="span"/> and encrypt into <paramref name="bufferWriter"/>
        /// </summary>
        /// <param name="span">Unencrypted buffer</param>
        /// <param name="bufferWriter">The buffer to ecnrypt to</param>
        /// <param name="totalRead">Total bytes read from the unencrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslStateExtensions.WantsRead(SslState)"/> or <see cref="SslStateExtensions.WantsWrite(SslState)"/> when the SSL connection needs data.</returns>
        public SslState WriteSsl
        (
            ReadOnlySpan<byte> readableBuffer,
            IBufferWriter<byte> bufferWriter,
            out int totalRead
        )
        {
            int readIndex = 0;
            int written;
            SslState sslState = SslState.NONE;
            ReadOnlySpan<byte> readBuf;

            readBuf = SliceReadableSpan
            (
                readableBuffer,
                readIndex,
                _MaxPairBufferSize
            );

            do
            {
                lock (this._lock)
                {
                    //allow to continue from previous write operation
                    while (!readBuf.IsEmpty)
                    {
                        //write unencrypted data into ssl
                        written = CryptoWrapper.BIO_write(this._sslBio, in MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        if (written <= 0)
                        {
                            totalRead = readIndex;
                            sslState = this.VerifyError(written);

                            if (sslState.WantsWrite())
                            {
                                break;
                            }

                            return sslState;
                        }
                        else
                        {
                            readIndex += written;
                        }

                        readBuf = SliceReadableSpan
                        (
                            readableBuffer,
                            readIndex,
                            _MaxPairBufferSize
                        );
                    }

                    //read encrypted data (or read pending if readBuf.IsEmpty)
                    sslState = this.ReadEncryptedIntoBufferWriter
                    (
                        bufferWriter
                    );
                }

                if (sslState > 0)
                {
                    break;
                }

            } while (!readBuf.IsEmpty);

            totalRead = readIndex;
            return sslState;
        }

        /// <summary>
        /// Write unencrypted data from <paramref name="sequence"/> and encrypt into <paramref name="bufferWriter"/>
        /// </summary>
        /// <param name="sequence">Unencrypted buffer</param>
        /// <param name="bufferWriter">The buffer to ecnrypt to</param>
        /// <param name="totalRead">Total bytes read from the unencrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslStateExtensions.WantsRead(SslState)"/> or <see cref="SslStateExtensions.WantsWrite(SslState)"/> when the SSL connection needs data.</returns>
        public SslState WriteSsl
        (
            in ReadOnlySequence<byte> sequence,
            IBufferWriter<byte> bufferWriter,
            out SequencePosition totalRead
        )
        {
            totalRead = sequence.Start;
            SslState sslState = SslState.NONE;

            //empty sequence will go through this path
            //this ensures a BIO_read occurs when the buffer is empty
            if (sequence.IsSingleSegment)
            {
                sslState = this.WriteSsl(sequence.FirstSpan, bufferWriter, out int read);
                totalRead = sequence.GetPosition(read);
                return sslState;
            }

            int written, totalIndex = 0;
            ReadOnlySpan<byte> span;
            ReadOnlySequence<byte> s;

            s = SliceReadOnlySequence
            (
                in sequence,
                sequence.Start,
                _MaxPairBufferSize
            );

            do
            {
                ReadOnlySequence<byte>.Enumerator memoryEnumerator = s.GetEnumerator();
                lock (this._lock)
                {
                    while (memoryEnumerator.MoveNext())
                    {
                        if (memoryEnumerator.Current.IsEmpty)
                        {
                            continue;
                        }

                        span = memoryEnumerator.Current.Span;

                        //write unencrypted data to the BIO
                        written = CryptoWrapper.BIO_write(this._sslBio, in MemoryMarshal.GetReference<byte>(span), span.Length);

                        if (written <= 0)
                        {
                            totalRead = sequence.GetPosition(totalIndex);
                            sslState = this.VerifyError(written);

                            if (sslState.WantsWrite())
                            {
                                break;
                            }

                            return sslState;
                        }
                        else
                        {
                            totalIndex += written;
                        }
                    }

                    //read encrypted data
                    sslState = this.ReadEncryptedIntoBufferWriter
                    (
                        bufferWriter
                    );
                }

                if (sslState > 0)
                {
                    break;
                }

                s = SliceReadOnlySequence
                (
                    in sequence,
                    s.End,
                    _MaxPairBufferSize
                );
            } while (!s.IsEmpty);

            totalRead = sequence.GetPosition(totalIndex);
            return sslState;
        }

        private SslState ReadEncryptedIntoBufferWriter
        (
            IBufferWriter<byte> bufferWriter
        )
        {
            int written;

            //check if any more data is pending to be written
            while (CryptoWrapper.BIO_ctrl_pending(this._netBio) > 0)
            {
                //get a buffer from the IBufferWriter with the correct frame size
                Span<byte> writeBuffer = bufferWriter.GetSpan(1);

                //and write encrypted data to the buffer received from IBufferWriter
                written = CryptoWrapper.BIO_read(this._netBio, ref MemoryMarshal.GetReference<byte>(writeBuffer), writeBuffer.Length);

                if (written <= 0)
                {
                    SslState sslState = this.VerifyError(written);

                    if(sslState.WantsWrite())
                    {
                        continue;
                    }

                    return sslState;
                }

                //advance the writer with the amount read
                bufferWriter.Advance(written);
            }

            //should be no more pending
            return this.VerifyState();
        }

        /// <summary>
        /// Check if the current SSL context is in an erroneous state
        /// </summary>
        /// <param name="ret">The return value from a previous read/write operation on the ssl context</param>
        /// <returns>A user handleable <see cref="SslState"/></returns>
        /// <exception cref="OpenSslException">When the SSL context is in an erroneous state</exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private SslState VerifyError
        (
            int ret
        )
        {
            Debug.Assert(Monitor.IsEntered(this._lock), "Lock not entered.");

            if (ret > 0)
            {
                return  SslState.NONE;
            }

            int errorCode = SSLWrapper.SSL_get_error(this._sslHandle, ret);
            SslError error = (SslError)errorCode;

            return this.MapNativeError(error, ret);
        }

        private SslState MapNativeError
        (
            SslError error,
            int ret
        )
        {
            Debug.Assert(Monitor.IsEntered(this._lock), "Lock not entered.");

            switch (error)
            {
                case SslError.SSL_ERROR_SSL:
                    try
                    {
                        //SSL error occured, check the currents thread error queue
                        throw new OpenSslException();
                    }
                    finally
                    {
                        CryptoWrapper.ERR_clear_error();
                    }
                case SslError.SSL_ERROR_SYSCALL:
                    return this.VerifySysCallError(ret);
                case SslError.SSL_ERROR_WANT_READ:
                case SslError.SSL_ERROR_WANT_WRITE:
                    return this.VerifyState();
                case SslError.SSL_ERROR_ZERO_RETURN:
                    return SslState.SHUTDOWN;
                case SslError.SSL_ERROR_NONE:
                default:
                    return SslState.NONE;
            }
        }
        //see https://github.com/dotnet/runtime/blob/d3af4921f36dba8dde35ade7dff59a3a192edddb/src/libraries/Common/src/Interop/Unix/System.Security.Cryptography.Native/Interop.OpenSsl.cs#L795
        private SslState VerifySysCallError
        (
            int ret
        )
        {
            //check if it's an OpenSsl error
            ulong sslErr = CryptoWrapper.ERR_peek_error();
            if (sslErr > 0)
            {
                try
                {
                    throw new OpenSslException();
                }
                finally
                {
                    CryptoWrapper.ERR_clear_error();
                }
            }

            //check last platform error
            int errno = Marshal.GetLastWin32Error();
            if (errno > 0)
            {
                throw new System.IO.IOException($"Platform IO error (errno {errno})");
            }

            if (ret == 0)
            {
                throw new System.IO.EndOfStreamException();
            }

            //might just be a 0 byte read/write with unknown retry code
            //might be a full BIO buffer (_MaxPairBufferSize)
            //retry/continue operation if it so wants to
            throw new System.IO.IOException();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private SslState VerifyState()
        {
            Debug.Assert(Monitor.IsEntered(this._lock), "Lock not entered.");

            SslState state = SslState.NONE;
            nuint ret = 0;

            if((ret = CryptoWrapper.BIO_ctrl_pending(this._netBio)) > 0)
            {
                state |= SslState.WANTWRITE;
            }

            if ((ret = CryptoWrapper.BIO_ctrl_get_read_request(this._netBio)) > 0)
            {
                state |= SslState.WANTREAD;
            }

            if ((ret = CryptoWrapper.BIO_ctrl_pending(this._sslBio)) > 0)
            {
                state |= SslState.READ_DATA_AVAILABLE;
            }

            if(SSLWrapper.SSL_get_shutdown(this._sslHandle) > 0)
            {
                state |= SslState.SHUTDOWN;
            }

            return state;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySequence<byte> SliceReadOnlySequence
        (
            in ReadOnlySequence<byte> buffer,
            SequencePosition start,
            long length
        )
        {
            if (buffer.Start.Equals(start)
                && buffer.Length <= length)
            {
                return buffer;
            }

            ReadOnlySequence<byte> t = buffer.Slice(start);
            if (t.Length <= length)
            {
                return t;
            }

            return buffer.Slice(start, length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<byte> SliceReadableSpan
        (
            ReadOnlySpan<byte> readableBuffer,
            int index,
            int maxLength
        )
        {
            if (readableBuffer.Length < index + maxLength)
            {
                return readableBuffer.Slice(index);

            }
            else
            {
                return readableBuffer.Slice(index, maxLength);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Span<byte> SliceSpan
        (
            Span<byte> writableBuffer,
            int index,
            int maxLength
        )
        {
            if (writableBuffer.Length < index + maxLength)
            {
                return writableBuffer.Slice(index);

            }
            else
            {
                return writableBuffer.Slice(index, maxLength);
            }
        }

        //helper functions for testing
#if DEBUG
        public long RenegotitationCount
        {
            get
            {
                return SSLWrapper.SSL_ctrl
                (
                    this._sslHandle,
                    10, //SSL_CTRL_GET_NUM_RENEGOTIATIONS
                    0,
                    IntPtr.Zero
                );
            }
        }
#endif

        private static void ThrowInvalidOperationException_HandshakeNotCompleted(bool handshakeCompleted)
        {
            if (!handshakeCompleted)
            {
                throw new InvalidOperationException("Handshake not completed yet");
            }
        }

        public void Dispose()
        {
            this.Dispose(true);

            GC.SuppressFinalize(this);
        }

        public void Dispose(bool isDisposing)
        {
            try
            {
                this._sslHandle.Dispose();
            }
            catch
            { }

            try
            {
                this._internalBio.Dispose();
            }
            catch
            { }

            try
            {
                this._netBio.Dispose();
            }
            catch
            { }

            try
            {
                this._sslBio.Dispose();
            }
            catch
            { }

            try
            {
                this._sslContext._sslContextHandle.DangerousRelease();
            }
            catch
            { }
        }
    }
}
