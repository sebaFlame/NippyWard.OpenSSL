using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Diagnostics;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using OpenSSL.Core.Interop.Wrappers;
using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.Error;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Collections;

namespace OpenSSL.Core.SSL
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

                using (SafeSslCipherHandle cipher = SSLWrapper.SSL_get_current_cipher(this._sslHandle))
                {
                    return Native.PtrToStringAnsi(SSLWrapper.SSL_CIPHER_get_name(cipher), false);
                }
            }
        }

        public SslProtocol Protocol
        {
            get
            {
                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                int versionNumber = SSLWrapper.SSL_version(this._sslHandle);
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

                return new X509Certificate(SSLWrapper.SSL_get_peer_certificate(this._sslHandle));
            }
        }

        public bool IsSessionReused
        {
            get
            {
                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                return SSLWrapper.SSL_session_reused(this._sslHandle) == 1;
            }
        }

        public X509Store CertificateStore
        {
            get => new X509Store(SSLWrapper.SSL_CTX_get_cert_store(this._sslContext._sslContextHandle));
        }

        /// <summary>
        /// Set.Get the certificate for this session.
        /// Can also be used to set the client certificate in client mode
        /// without using a client certificate callback
        /// </summary>
        public X509Certificate Certificate
        {
            get => new X509Certificate(SSLWrapper.SSL_CTX_get0_certificate(this._sslContext._sslContextHandle));
        }

        /// <summary>
        /// Set/Gets the private key for this session
        /// </summary>
        public PrivateKey PrivateKey
        {
            get => PrivateKey.GetCorrectKey(SSLWrapper.SSL_CTX_get0_privatekey(this._sslContext._sslContextHandle));
        }

        /// <summary>
        /// Gets the session for the current context
        /// </summary>
        public SslSession Session
        {
            get
            {
                //server side does not use a session
                if(this.IsServer)
                {
                    return null;
                }

                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                return new SslSession(this._sslContext._sessionHandle);
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

        public bool IsServer => this._isServer;
        /// <summary>
        /// Reusable SSL context. Eg for session reuse between multiple clients on a server.
        /// </summary>
        public SslContext SslContext => this._sslContext;

        public const SslStrength _DefaultSslStrength = SslStrength.Level2;
        public const SslProtocol _DefaultSslProtocol = SslProtocol.Tls12 | SslProtocol.Tls13;

        #region native handles
        private readonly SafeBioHandle _readHandle;
        private readonly SafeBioHandle _writeHandle;
        private readonly SafeSslHandle _sslHandle;
        #endregion

        private bool _handshakeCompleted;
        private readonly bool _isServer;
        private readonly SslContext _sslContext;

        //a single lock to facilitate SSL state changes
        private readonly object _lock;

        //a global state to hold state from different (read/write) threads
        //only mutated inside _lock
        private SslState _state;

        //pinned delegate
        private readonly SslInfoCallback _infoCb;

        private const int _MaxUnencryptedLength = Native.SSL3_RT_MAX_PLAIN_LENGTH;
        //guarantee atleast 1 record (TLS1.3 has smaller packet size)
        //TODO: benchmark with Native.SSL3_RT_MAX_PACKET_SIZE + (int)(Native.SSL3_RT_MAX_PACKET_SIZE * 0.5) + 1
        private const int _MaxEncryptedLength = Native.SSL3_RT_MAX_PACKET_SIZE + 1;

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
            X509Store certificateStore = null,
            X509Certificate certificate = null,
            PrivateKey privateKey = null,
            ClientCertificateCallbackHandler clientCertificateCallbackHandler = null,
            RemoteCertificateValidationHandler remoteCertificateValidationHandler = null,
            SslSession previousSession = null,
            IEnumerable<string> ciphers = null
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
            X509Store certificateStore = null,
            X509Certificate certificate = null,
            PrivateKey privateKey = null,
            ClientCertificateCallbackHandler clientCertificateCallbackHandler = null,
            RemoteCertificateValidationHandler remoteCertificateValidationHandler = null,
            SslSession previousSession = null,
            IEnumerable<string> ciphers = null
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

        private Ssl()
        {
            this._lock = new object();
        }

        private Ssl
        (
            bool isServer,
            SslContext sslContext,
            SslSession previousSession = null
        ) : this()
        {
            //add a (managed) reference, so the object can be reused
            bool success = true;
            sslContext._sslContextHandle.DangerousAddRef(ref success);

            //DangerousAddRef either throws an exception
            //or returns success
            if (!success)
            {
                throw new InvalidOperationException("Can not happen???");
            }

            SafeBioHandle readHandle = null, writeHandle = null;
            SafeSslHandle sslHandle = null;
            try
            {
                readHandle = CryptoWrapper.BIO_new(CryptoWrapper.BIO_s_mem());
                writeHandle = CryptoWrapper.BIO_new(CryptoWrapper.BIO_s_mem());

                sslHandle = SSLWrapper.SSL_new(sslContext._sslContextHandle);
                SSLWrapper.SSL_set_bio(sslHandle, readHandle, writeHandle);

                //set callback to check for state changes
                SSLWrapper.SSL_set_info_callback
                (
                    sslHandle,
                    this._infoCb = new SslInfoCallback(this.SslInfoCallback)
                );
            }
            catch (Exception)
            {
                readHandle?.Dispose();
                writeHandle?.Dispose();
                sslHandle?.Dispose();

                throw;
            }

            //assign relevant fields
            this._sslContext = sslContext;
            this._readHandle = readHandle;
            this._writeHandle = writeHandle;
            this._sslHandle = sslHandle;

            //add references for correct disposal
            this._readHandle.AddReference();
            this._writeHandle.AddReference();

            //set correct connection endpoint options
            if (isServer)
            {
                SSLWrapper.SSL_set_accept_state(this._sslHandle);
            }
            else
            {
                SSLWrapper.SSL_set_connect_state(this._sslHandle);
            }

            //enable session reuse
            if (previousSession is not null)
            {
                SSLWrapper.SSL_set_session(this._sslHandle, previousSession.SessionWrapper.Handle);
            }

            this._handshakeCompleted = false;
            this._isServer = isServer;
        }

        ~Ssl()
        {
            this.Dispose(false);
        }

        //this callback check if the internal SSL state changed and if
        //a write is needed. If so this._state gets mutated into the
        //correct state.
        //This callback only gets called when the internal state machine
        //changes (eg during handshake or renegotiate).
        //ensure this only gets called in a locked this._lock
        private void SslInfoCallback(IntPtr ssl, int where, int ret)
        {
            Debug.Assert(Monitor.IsEntered(this._lock));
            CheckForWrite(this._sslHandle, where, ref this._state);
        }

        private static void CheckForWrite
        (
            SafeSslHandle ssl,
            int where,
            ref SslState sslState
        )
        {
            //state changed
            if ((where & Native.SSL_CB_LOOP) > 0)
            {
                //get the current state
                IntPtr ptr = SSLWrapper.SSL_state_string(ssl);

                //get 2nd ASCII char
                byte b = Marshal.ReadByte(ptr, 1);

                //if it's a W, a write happened
                if (b == (byte)'W')
                {
                    sslState |= SslState.WANTWRITE;
                }
            }
            //write cb (eg during shutdown)
            else if ((where & Native.SSL_CB_WRITE) > 0)
            {
                sslState |= SslState.WANTWRITE;
            }
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
            SslState writeState;

            lock (this._lock)
            {
                this._state = default;
                ret_code = SSLWrapper.SSL_do_handshake(this._sslHandle);
                writeState = this._state;
            }

            //get next action from OpenSSL wrapper
            if (ret_code == 1)
            {
                state = VerifyStageState(in writeState);

                if (state != SslState.NONE)
                {
                    return false;
                }

                this._handshakeCompleted = true;
                return true;
            }
            else if (ret_code == 0)
            {
                state = VerifyStageState(in writeState);
                return false;
            }
            else
            {
                state = this.VerifyError(ret_code, in writeState);
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
            SslState writeState;

            try
            {
                lock (this._lock)
                {
                    this._state = default;
                    ret_code = SSLWrapper.SSL_shutdown(this._sslHandle);
                    writeState = this._state;
                }

                //initialize (or continue) a shutdown
                if (ret_code == 1)
                {
                    state = VerifyStageState(in writeState);
                    return state == SslState.NONE;
                }
                else if (ret_code == 0)
                {
                    //force check bio states
                    state = VerifyStageState(in writeState);
                    return false;
                }
                else
                {
                    state = this.VerifyError(ret_code, in writeState);
                    return false;
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
        public SslState DoRenegotiate()
        {
            ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

            SslState sslState;

            //ensure the renegotiate/handshake function get executed together
            //so no read/write gets inbetween
            lock (this._lock)
            {
                //these functions do not change state and rely on SSL_do_handshake instead -> no lock
                if (this.Protocol == SslProtocol.Tls13)
                {
                    SSLWrapper.SSL_key_update(this._sslHandle, 1);
                }
                else
                {
                    SSLWrapper.SSL_renegotiate_abbreviated(this._sslHandle);
                }

                if (this.DoHandshake(out sslState))
                {
                    throw new InvalidOperationException("Handshake should not have completed during renegotiate initialization");
                }
            }

            return sslState;
        }

        /// <summary>
        /// Read encrypted data from <paramref name="readableBuffer"/> and decrypt into <paramref name="writableBuffer"/>
        /// </summary>
        /// <param name="readableBuffer">Encrypted buffer</param>
        /// <param name="writableBuffer">The buffer to decrypt to</param>
        /// <param name="totalRead">Total bytes read from the encrypted buffer</param>
        /// <param name="totalWritten">Total bytes written to decrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslState.WANTREAD"/> or <see cref="SslState.WANTWRITE"/> when the SSL connection needs data.</returns>
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
            int written = 0, read = 0;
            SslState sslState;

            ReadOnlySpan<byte> readBuf;
            Span<byte> writeBuf;

            CryptoWrapper.ERR_clear_error();

            readBuf = SliceReadableSpan
            (
                readableBuffer,
                readIndex,
                _MaxEncryptedLength
            );

            do
            {
                //keep both the BIO and the SSL inside the lock, so we don't get (unexpected) concurrency issues
                //during SSL state changes
                lock (this._lock)
                {
                    //allow to continue from previous read operation
                    if (!readBuf.IsEmpty)
                    {
                        //write a (possible) packet of encrypted data to the BIO
                        written = CryptoWrapper.BIO_write(this._readHandle, in MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        if (written < 0)
                        {
                            throw new OpenSslException();
                        }

                        //increment read index
                        readIndex += written;

                        //create new buffer
                        readBuf = SliceReadableSpan
                        (
                            readableBuffer,
                            readIndex,
                            _MaxEncryptedLength
                        );
                    }

                    writeBuf = SliceSpan
                    (
                        writableBuffer,
                        writeIndex,
                        _MaxUnencryptedLength
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

                //no more data can be written
                if (writeIndex == writableBuffer.Length
                    || (sslState.WantsRead()
                        && readBuf.IsEmpty)
                    || !(sslState == SslState.NONE
                        || sslState.WantsRead()))
                {
                    totalRead = readIndex;
                    totalWritten = writeIndex;
                    return sslState;
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
            int read = 0;

            //writeableBuffer CAN be empty, allow to force a "flush" of non-application data

            SslState sslState;

            //reset state
            this._state = default;

            //and write decrypted data to the buffer or flush read data
            read = SSLWrapper.SSL_read(this._sslHandle, ref MemoryMarshal.GetReference<byte>(writeableBuffer), writeableBuffer.Length);

            //get the current state after (possible) cb
            sslState = this._state;

            if (read <= 0)
            {
                totalWritten = 0;
                return this.VerifyError(read, in sslState);
            }

            totalWritten = read;
            return this.VerifyReadState(out _);
        }

        /// <summary>
        /// Read encrypted data from <paramref name="span"/> and decrypt into <paramref name="bufferWriter"/>
        /// </summary>
        /// <param name="span">Encrypted buffer</param>
        /// <param name="bufferWriter">The buffer to decrypt to</param>
        /// <param name="totalRead">Total bytes read from the encrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslState.WANTREAD"/> or <see cref="SslState.WANTWRITE"/> when the SSL connection needs data.</returns>
        public SslState ReadSsl
        (
            ReadOnlySpan<byte> readableBuffer,
            IBufferWriter<byte> bufferWriter,
            out int totalRead
        )
        {
            int readIndex = 0;
            int written = 0;
            SslState sslState;
            ReadOnlySpan<byte> readBuf;

            //do not allow flushing/retry behaviour
            ////bufferwriter is always writable
            if (readableBuffer.IsEmpty)
            {
                totalRead = 0;
                return SslState.NONE;
            }

            CryptoWrapper.ERR_clear_error();

            readBuf = SliceReadableSpan
            (
                readableBuffer,
                readIndex,
                _MaxEncryptedLength
            );

            do
            {
                lock (this._lock)
                {
                    //allow to continue from previous read operation
                    if (!readBuf.IsEmpty)
                    {
                        //write a (possible) packet of encrypted data to the BIO
                        written = CryptoWrapper.BIO_write(this._readHandle, in MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        if (written < 0)
                        {
                            throw new OpenSslException();
                        }

                        //increment read index
                        readIndex += written;

                        readBuf = SliceReadableSpan
                        (
                            readableBuffer,
                            readIndex,
                            _MaxEncryptedLength
                        );
                    }

                    //allow for atleast a flush
                    //then read the (unencrypted) buffer into the bufferwriter
                    sslState = this.ReadUnencryptedIntoBufferWriter
                    (
                        bufferWriter
                    );
                }

                if ((sslState.WantsRead()
                        && readBuf.IsEmpty)
                    || !(sslState == SslState.NONE
                        || sslState.WantsRead()))
                {
                    totalRead = readIndex;
                    return sslState;
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
        /// <see cref="SslState.WANTREAD"/> or <see cref="SslState.WANTWRITE"/> when the SSL connection needs data.</returns>
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

            //do not allow flushing/retry behaviour
            ////bufferwriter is always writable
            if (sequence.IsEmpty)
            {
                return SslState.NONE;
            }

            if (sequence.IsSingleSegment)
            {
                sslState = this.ReadSsl(sequence.FirstSpan, bufferWriter, out read);
                totalRead = sequence.GetPosition(read);
                return sslState;
            }

            int written = 0, totalIndex = 0;
            int readIndex = 0;
            ReadOnlySpan<byte> readBuf, span;

            CryptoWrapper.ERR_clear_error();

            ReadOnlySequence<byte>.Enumerator memoryEnumerator = sequence.GetEnumerator();
            while (memoryEnumerator.MoveNext())
            {
                span = memoryEnumerator.Current.Span;

                readIndex = 0;

                readBuf = SliceReadableSpan
                (
                    span,
                    readIndex,
                    _MaxEncryptedLength
                );

                while (!readBuf.IsEmpty)
                {
                    lock (this._lock)
                    {
                        //write a (possible) packet of encrypted data to the BIO
                        written = CryptoWrapper.BIO_write(this._readHandle, in MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        if (written < 0)
                        {
                            throw new OpenSslException();
                        }

                        //increment read index
                        readIndex += written;
                        totalIndex += written;

                        //create new buffer
                        readBuf = SliceReadableSpan
                        (
                            span,
                            readIndex,
                            _MaxEncryptedLength
                        );

                        //then read the (unencrypted) buffer into the bufferwriter
                        sslState = this.ReadUnencryptedIntoBufferWriter
                        (
                            bufferWriter
                        );
                    }

                    if (sslState.WantsRead())
                    {
                        //still data in current buffer
                        if (!readBuf.IsEmpty)
                        {
                            continue;
                        }
                        //if another memory is available, continue
                        else if (memoryEnumerator.MoveNext())
                        {
                            span = memoryEnumerator.Current.Span;

                            readIndex = 0;

                            readBuf = SliceReadableSpan
                            (
                                span,
                                readIndex,
                                _MaxEncryptedLength
                            );

                            continue;
                        }
                        //return if no more memory in sequence
                        else
                        {
                            totalRead = sequence.GetPosition(totalIndex);
                            return sslState;
                        }
                    }
                    else if (sslState != SslState.NONE)
                    {
                        totalRead = sequence.GetPosition(totalIndex);
                        return sslState;
                    }
                }
            }

            //get the position which has been read to
            totalRead = sequence.GetPosition(totalIndex);

            return sslState;
        }

        private SslState ReadUnencryptedIntoBufferWriter
        (
            IBufferWriter<byte> bufferWriter
        )
        {
            int read = 0, pending = 0;
            SslState sslState;
            Span<byte> writeBuffer;

            do
            {
                //get a buffer from the IBufferWriter (of unkown length - use 16384 as default)
                pending = pending == 0 ? _MaxUnencryptedLength : pending;
                writeBuffer = bufferWriter.GetSpan(pending);

                //reset current state
                this._state = default;

                //and write decrypted data to the buffer received from IBufferWriter
                read = SSLWrapper.SSL_read(this._sslHandle, ref MemoryMarshal.GetReference<byte>(writeBuffer), writeBuffer.Length);

                //read new state
                sslState = this._state;

                if (read <= 0)
                {
                    return this.VerifyError(read, in sslState);
                }

                //advance buffer writer with the amount read
                bufferWriter.Advance(read);
            } while ((sslState = this.VerifyReadState(out pending)) == SslState.WANTREAD);

            return sslState;
        }

        /// <summary>
        /// Write unencrypted data from <paramref name="readableBuffer"/> and encrypt into <paramref name="writableBuffer"/>
        /// </summary>
        /// <param name="readableBuffer">Unencrypted buffer</param>
        /// <param name="writableBuffer">The buffer to ecnrypt to</param>
        /// <param name="totalRead">Total bytes read from the unencrypted buffer</param>
        /// <param name="totalWritten">Total bytes written into the encrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslState.WANTREAD"/> or <see cref="SslState.WANTWRITE"/> when the SSL connection needs data.</returns>
        public SslState WriteSsl
        (
            ReadOnlySpan<byte> readableBuffer,
            Span<byte> writableBuffer,
            out int totalRead,
            out int totalWritten
        )
        {
            int readIndex = 0, writeIndex = 0;
            int written = 0, read = 0;
            SslState sslState = SslState.NONE;

            ReadOnlySpan<byte> readBuf;
            Span<byte> writeBuf;

            CryptoWrapper.ERR_clear_error();

            readBuf = SliceReadableSpan
            (
                readableBuffer,
                readIndex,
                _MaxUnencryptedLength
            );

            do
            {
                lock (this._lock)
                {
                    //allow to continue from previous write operation
                    if (!readBuf.IsEmpty)
                    {
                        //reset current state
                        this._state = default;

                        //write unencrypted data into ssl
                        written = SSLWrapper.SSL_write(this._sslHandle, MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        //get new state after cb (TODO: needed?)
                        sslState = this._state;

                        if (written <= 0)
                        {
                            totalRead = readIndex;
                            totalWritten = writeIndex;

                            return this.VerifyError(written, in sslState);
                        }

                        readIndex += written;

                        readBuf = SliceReadableSpan
                        (
                            readableBuffer,
                            readIndex,
                            _MaxUnencryptedLength
                        );
                    }

                    writeBuf = SliceSpan
                    (
                        writableBuffer,
                        writeIndex,
                        _MaxEncryptedLength
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
                if (writeIndex == writableBuffer.Length
                    || (sslState.WantsWrite()
                        && readBuf.IsEmpty)
                    || !(sslState == SslState.NONE
                        || sslState.WantsWrite()))
                {
                    totalRead = readIndex;
                    totalWritten = writeIndex;
                    return sslState;
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
            int written = 0;

            if (writableBuffer.IsEmpty)
            {
                totalWritten = 0;
                return this.VerifyWriteState();
            }

            //check if any more data is pending to be written
            if (CryptoWrapper.BIO_ctrl_pending(this._writeHandle) == 0)
            {
                totalWritten = 0;
                return SslState.NONE;
            }

            //and write encrypted data to the buffer received from IBufferWriter
            written = CryptoWrapper.BIO_read(this._writeHandle, ref MemoryMarshal.GetReference<byte>(writableBuffer), writableBuffer.Length);

            if (written < 0)
            {
                throw new OpenSslException();
            }

            totalWritten = written;

            return this.VerifyWriteState();
        }

        /// <summary>
        /// Write unencrypted data from <paramref name="span"/> and encrypt into <paramref name="bufferWriter"/>
        /// </summary>
        /// <param name="span">Unencrypted buffer</param>
        /// <param name="bufferWriter">The buffer to ecnrypt to</param>
        /// <param name="totalRead">Total bytes read from the unencrypted buffer</param>
        /// <returns><see cref="SslState.NONE"/> when no action is needed.
        /// <see cref="SslState.WANTREAD"/> or <see cref="SslState.WANTWRITE"/> when the SSL connection needs data.</returns>
        public SslState WriteSsl
        (
            ReadOnlySpan<byte> readableBuffer,
            IBufferWriter<byte> bufferWriter,
            out int totalRead
        )
        {
            int readIndex = 0;
            int written = 0;
            SslState sslState;
            ReadOnlySpan<byte> readBuf;

            CryptoWrapper.ERR_clear_error();

            readBuf = SliceReadableSpan
            (
                readableBuffer,
                readIndex,
                _MaxUnencryptedLength
            );

            do
            {
                lock (this._lock)
                {
                    //allow to continue from previous write operation
                    if (!readBuf.IsEmpty)
                    {
                        this._state = default;

                        //write unencrypted data into ssl
                        written = SSLWrapper.SSL_write(this._sslHandle, MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        //get new state after possible cb (TODO: needed?)
                        sslState = this._state;

                        if (written <= 0)
                        {
                            totalRead = readIndex;
                            return this.VerifyError(written, in sslState);
                        }

                        readIndex += written;

                        readBuf = SliceReadableSpan
                        (
                            readableBuffer,
                            readIndex,
                            _MaxUnencryptedLength
                        );
                    }

                    //read encrypted data (or read pending if readBuf.IsEmpty)
                    sslState = this.ReadEncryptedIntoBufferWriter
                    (
                        bufferWriter
                    );
                }

                if ((sslState.WantsWrite()
                        && readBuf.IsEmpty)
                    || !(sslState == SslState.NONE
                        || sslState.WantsWrite()))
                {
                    totalRead = readIndex;
                    return sslState;
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
        /// <see cref="SslState.WANTREAD"/> or <see cref="SslState.WANTWRITE"/> when the SSL connection needs data.</returns>
        public SslState WriteSsl
        (
            in ReadOnlySequence<byte> sequence,
            IBufferWriter<byte> bufferWriter,
            out SequencePosition totalRead
        )
        {
            totalRead = sequence.Start;
            SslState sslState = SslState.NONE;

            if (sequence.IsSingleSegment)
            {
                sslState = this.WriteSsl(sequence.FirstSpan, bufferWriter, out int read);
                totalRead = sequence.GetPosition(read);
                return sslState;
            }

            int written = 0, readIndex = 0, totalIndex = 0;
            ReadOnlySpan<byte> span, readBuf;

            CryptoWrapper.ERR_clear_error();

            ReadOnlySequence<byte>.Enumerator memoryEnumerator = sequence.GetEnumerator();
            while (memoryEnumerator.MoveNext())
            {
                span = memoryEnumerator.Current.Span;
                readIndex = 0;

                readBuf = SliceReadableSpan
                (
                    span,
                    readIndex,
                    _MaxUnencryptedLength
                );

                while (!readBuf.IsEmpty)
                {
                    lock (this._lock)
                    {
                        this._state = default;

                        //write unencrypted data to the BIO
                        written = SSLWrapper.SSL_write(this._sslHandle, in MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                        //get new state after possible cb (TODO: needed?)
                        sslState = this._state;

                        if (written <= 0)
                        {
                            totalRead = sequence.GetPosition(totalIndex);
                            return this.VerifyError(written, in sslState);
                        }

                        readIndex += written;
                        totalIndex += written;

                        readBuf = SliceReadableSpan
                        (
                            span,
                            readIndex,
                            _MaxUnencryptedLength
                        );

                        //read encrypted data
                        sslState = this.ReadEncryptedIntoBufferWriter
                        (
                            bufferWriter
                        );
                    }

                    if (sslState.WantsWrite())
                    {
                        if (!readBuf.IsEmpty)
                        {
                            continue;
                        }
                        //if another memory is available, continue
                        else if (memoryEnumerator.MoveNext())
                        {
                            span = memoryEnumerator.Current.Span;

                            readIndex = 0;

                            readBuf = SliceReadableSpan
                            (
                                span,
                                readIndex,
                                _MaxEncryptedLength
                            );

                            continue;
                        }
                        //return if no more memory in sequence
                        else
                        {
                            totalRead = sequence.GetPosition(totalIndex);
                            return sslState;
                        }
                    }
                    else if (sslState != SslState.NONE)
                    {
                        totalRead = sequence.GetPosition(totalIndex);
                        return sslState;
                    }
                }
            }

            totalRead = sequence.GetPosition(totalIndex);
            return sslState;
        }

        private SslState ReadEncryptedIntoBufferWriter
        (
            IBufferWriter<byte> bufferWriter
        )
        {
            int written = 0, pending = 0;

            //check if any more data is pending to be written
            while ((pending = (int)CryptoWrapper.BIO_ctrl_pending(this._writeHandle)) > 0)
            {
                //ensure correct packet size
                pending = pending > _MaxEncryptedLength ? _MaxEncryptedLength : pending;

                //get a buffer from the IBufferWriter with the correct frame size
                Span<byte> writeBuffer = bufferWriter.GetSpan(pending);

                //and write encrypted data to the buffer received from IBufferWriter
                written = CryptoWrapper.BIO_read(this._writeHandle, ref MemoryMarshal.GetReference<byte>(writeBuffer), writeBuffer.Length);

                if (written < 0)
                {
                    throw new OpenSslException();
                }

                //advance the writer with the amount read
                bufferWriter.Advance(written);
            };

            //should be no more pending
            return this.VerifyWriteState();
        }

        /// <summary>
        /// Check if the current SSL context is in an erroneous state
        /// </summary>
        /// <param name="ret">The return value from a previous read/write operation on the ssl context</param>
        /// <returns>A user handleable <see cref="SslState"/></returns>
        /// <exception cref="ShutdownException">When a shutdown has already occured</exception>
        /// <exception cref="OpenSslException">When the SSL context is in an erroneous state</exception>
        private SslState VerifyError
        (
            int ret,
            in SslState opState
        )
        {
            if (ret > 0)
            {
                return SslState.NONE;
            }

            int errorCode = SSLWrapper.SSL_get_error(this._sslHandle, ret);
            SslError error = (SslError)errorCode;

            return MapNativeError(error, in opState);
        }

        private static SslState MapNativeError
        (
            SslError error,
            in SslState opState
        )
        {
            switch (error)
            {
                case SslError.SSL_ERROR_SYSCALL:
                case SslError.SSL_ERROR_SSL:
                    //error of different kind happened, check the currents thread error queue
                    throw new OpenSslException();
                case SslError.SSL_ERROR_WANT_READ:
                case SslError.SSL_ERROR_WANT_WRITE:
                    return VerifyStageState(in opState, error);
                case SslError.SSL_ERROR_ZERO_RETURN:
                    return SslState.SHUTDOWN;
                case SslError.SSL_ERROR_NONE:
                default:
                    return SslState.NONE;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static SslState VerifyStageState
        (
            in SslState sslState,
            SslError error = SslError.SSL_ERROR_NONE
        )
        {
            //prioritize writes
            if ((sslState & SslState.WANTWRITE) > 0)
            {
                return SslState.WANTWRITE;
            }
            else if ((sslState & SslState.WANTREAD) > 0)
            {
                return SslState.WANTREAD;
            }

            return MapNativeReadWriteError(error);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static SslState MapNativeReadWriteError(SslError error)
        {
            switch (error)
            {
                case SslError.SSL_ERROR_WANT_READ:
                    return SslState.WANTREAD;
                case SslError.SSL_ERROR_WANT_WRITE:
                    return SslState.WANTWRITE;
                case SslError.SSL_ERROR_NONE:
                    return SslState.NONE;
                default:
                    throw new NotSupportedException($"Unsupported read/write error {error}");
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private SslState VerifyReadState(out int pending)
        {
            if ((pending = SSLWrapper.SSL_pending(this._sslHandle)) > 0
                || CryptoWrapper.BIO_ctrl_pending(this._readHandle) > 0)
            {
                return SslState.WANTREAD;
            }
            else
            {
                return SslState.NONE;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private SslState VerifyWriteState()
        {
            if (CryptoWrapper.BIO_ctrl_pending(this._writeHandle) > 0)
            {
                return SslState.WANTWRITE;
            }
            else
            {
                return SslState.NONE;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<byte> SliceReadableSpan
        (
            in ReadOnlySpan<byte> readableBuffer,
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
            in Span<byte> writableBuffer,
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
        public bool IsRenegotiatePending
        {
            get
            {
                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                return SSLWrapper.SSL_renegotiate_pending(this._sslHandle) == 1;
            }
        }

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
        }

        public void Dispose(bool isDisposing)
        {
            try
            {
                this._sslHandle?.Dispose();
            }
            catch (Exception)
            { }

            try
            {
                this._readHandle?.Dispose();
            }
            catch (Exception)
            { }

            try
            {
                this._writeHandle?.Dispose();
            }
            catch (Exception)
            { }

            try
            {
                this._sslContext?._sslContextHandle.DangerousRelease();
            }
            catch (Exception)
            { }

            if (!isDisposing)
            {
                return;
            }

            GC.SuppressFinalize(this);
        }
    }
}
