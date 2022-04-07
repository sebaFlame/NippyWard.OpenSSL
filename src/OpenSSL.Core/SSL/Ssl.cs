using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

using System.IO.Pipelines;

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

        #region native handles
        private readonly SafeBioHandle _readHandle;
        private readonly SafeBioHandle _writeHandle;
        private readonly SafeSslHandle _sslHandle;
        #endregion

        private bool _handshakeCompleted;
        private readonly bool _isServer;
        private readonly SslContext _sslContext;

        private const SslStrength _DefaultSslStrength = SslStrength.Level2;
        private const SslProtocol _DefaultSslProtocol = SslProtocol.Tls12 | SslProtocol.Tls13;
        private const int _MaxUnencryptedLength = Native.SSL3_RT_MAX_PLAIN_LENGTH;
        //guarantee atleast 1 record (TLS1.3 has smaller packet size)
        private const int _MaxEncryptedLength = Native.SSL3_RT_MAX_PACKET_SIZE + (int)(Native.SSL3_RT_MAX_PACKET_SIZE * 0.5) + 1;

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

        private Ssl
        (
            bool isServer,
            SslContext sslContext,
            SslSession previousSession = null
        )
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
            }
            catch(Exception)
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
            if(previousSession is not null)
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

            //get next action from OpenSSL wrapper
            if ((ret_code = SSLWrapper.SSL_do_handshake(this._sslHandle)) == 1)
            {
                //force check of non-blocking write BIO
                state = SslState.NONE;

                if (CryptoWrapper.BIO_ctrl_pending(this._writeHandle) > 0)
                {
                    state = SslState.WANTWRITE;
                    return false;
                }

                this._handshakeCompleted = true;
                return true;
            }

            state = this.VerifyError(ret_code);
            return false;
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
                //initialize (or continue) a shutdown
                if ((ret_code = SSLWrapper.SSL_shutdown(this._sslHandle)) == 1)
                {
                    state = SslState.NONE;
                    return true;
                }
                else if (ret_code == 0)
                {
                    state = SslState.WANTREAD;

                    //force check of non-blocking write BIO
                    if (CryptoWrapper.BIO_ctrl_pending(this._writeHandle) > 0)
                    {
                        state = SslState.WANTWRITE;
                    }

                    return false;
                }
                else
                {
                    state = this.VerifyError(ret_code);
                    return false;
                }
            }
            finally
            {
                //set the ssl context as "handshake not completed"
                this._handshakeCompleted = false;
            }
        }

        public SslState ReadSsl
        (
            ReadOnlySpan<byte> readableBuffer,
            out int totalRead
        )
        {
            Span<byte> writableBuffer = Span<byte>.Empty;

            return this.ReadSsl
            (
                readableBuffer,
                writableBuffer,
                out totalRead,
                out _
            );
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

            if(readableBuffer.Length < _MaxEncryptedLength)
            {
                readBuf = readableBuffer;
            }
            else
            {
                 readBuf = readableBuffer.Slice(readIndex, _MaxEncryptedLength);
            }

            do
            {
                //allow to continue from previous read operation
                if(!readBuf.IsEmpty)
                {
                    //write a (possible) packet of encrypted data to the BIO
                    written = CryptoWrapper.BIO_write(this._readHandle, in MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                    if (written < 0)
                    {
                        throw new OpenSslException();
                    }

                    //increment read index
                    readIndex += written;
                }

                //prepare write buffer
                if (writableBuffer.Length < writeIndex + _MaxUnencryptedLength)
                {
                    writeBuf = writableBuffer.Slice(writeIndex);
                }
                else
                {
                    writeBuf = writableBuffer.Slice(writeIndex, _MaxUnencryptedLength);
                }

                //then read the (unencrypted) buffer into the bufferwriter
                sslState = this.ReadUnencryptedIntoBuffer
                (
                    writeBuf,
                    out read
                );

                //increase write index
                writeIndex += read;

                //no more data can be written
                if (writeIndex == writableBuffer.Length)
                {
                    totalRead = readIndex;
                    totalWritten = writeIndex;
                    return sslState;
                }

                //prepare next read buffer
                if(readableBuffer.Length < readIndex + _MaxEncryptedLength)
                {
                    readBuf = readableBuffer.Slice(readIndex);
                    
                }
                else
                {
                    readBuf = readableBuffer.Slice(readIndex, _MaxEncryptedLength);
                }
                
            } while (readBuf.Length > 0);

            totalRead = readIndex;
            totalWritten = writeIndex;
            return sslState;
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
            ReadOnlySpan<byte> span,
            IBufferWriter<byte> bufferWriter,
            out int totalRead
        )
        {
            ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

            totalRead = 0;

            if(span.IsEmpty)
            {
                return SslState.NONE;
            }

            //write encrypted data to the BIO
            int written = CryptoWrapper.BIO_write(this._readHandle, in MemoryMarshal.GetReference<byte>(span), span.Length);

            if(written < 0)
            {
                throw new OpenSslException();
            }

            totalRead = written;

            //then read the (unencrypted) buffer into the bufferwriter
            return this.ReadSslIntoBufferWriter(bufferWriter);
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
            ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

            totalRead = sequence.Start;
            SslState state;
            int read;

            if (sequence.IsEmpty)
            {
                return SslState.NONE;
            }

            if(sequence.IsSingleSegment)
            {
                state = this.ReadSsl(sequence.FirstSpan, bufferWriter, out read);
                totalRead = sequence.GetPosition(read);
                return state;
            }

            int written = 0, totalWritten = 0;
            ReadOnlySpan<byte> span;

            //first write the complete (multi segment) (encrypted) buffer
            foreach(ReadOnlyMemory<byte> memory in sequence)
            {
                if(memory.IsEmpty)
                {
                    continue;
                }

                //get the span
                span = memory.Span;

                //write encrypted data to the BIO
                written = CryptoWrapper.BIO_write(this._readHandle, in MemoryMarshal.GetReference<byte>(span), span.Length);

                if(written < 0)
                {
                    throw new OpenSslException();
                }

                //increase total written to BIO
                totalWritten += written;

                if (written < span.Length)
                {
                    break;
                }
            }

            //get the position which has been read to
            totalRead = sequence.GetPosition(totalWritten);

            //then read the (unencrypted) buffer into the bufferwriter
            return this.ReadSslIntoBufferWriter(bufferWriter);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static SslState VerifyReadState
        (
            SafeBioHandle readHandle,
            SafeSslHandle sslHandle
        )
        {
            if (CryptoWrapper.BIO_ctrl_pending(readHandle) > 0
                || SSLWrapper.SSL_pending(sslHandle) > 0)
            {
                return SslState.WANTREAD;
            }
            else
            {
                return SslState.NONE;
            }
        }

        private SslState ReadUnencryptedIntoBuffer
        (
            Span<byte> writeableBuffer,
            out int totalWritten
        )
        {
            int read = 0;
            SslState sslState;

            //writeableBuffer CAN be empty, allow to force a "flush" of non-application data

            //if nothing is pending, early return
            if (CryptoWrapper.BIO_ctrl_pending(this._readHandle) == 0
                && SSLWrapper.SSL_pending(this._sslHandle) == 0)
            {
                totalWritten = 0;
                return SslState.NONE;
            }

            //and write decrypted data to the buffer or flush read data
            read = SSLWrapper.SSL_read(this._sslHandle, ref MemoryMarshal.GetReference<byte>(writeableBuffer), writeableBuffer.Length);

            if ((sslState = this.VerifyError(read)) > 0)
            {
                totalWritten = 0;

                //if(sslState == SslState.WANTREAD)
                //{
                //    return VerifyReadState(this._readHandle, this._sslHandle);
                //}

                return sslState;
            }

            totalWritten = read;

            return VerifyReadState(this._readHandle, this._sslHandle);
        }

        private SslState ReadSslIntoBufferWriter
        (
            IBufferWriter<byte> bufferWriter
        )
        {
            int read = 0, pending = 0;
            SslState sslState;
            Span<byte> writeBuffer;
            Span<byte> empty = Span<byte>.Empty;

            //check if any more data is pending to be read
            while((pending = (int)CryptoWrapper.BIO_ctrl_pending(this._readHandle)) > 0)
            {
                //get a buffer from the IBufferWriter (of unkown length - use 16384 as default)
                pending = Native.SSL3_RT_MAX_PLAIN_LENGTH;

                do
                {
                    writeBuffer = bufferWriter.GetSpan(pending);

                    //and write decrypted data to the buffer received from IBufferWriter
                    read = SSLWrapper.SSL_read(this._sslHandle, ref MemoryMarshal.GetReference<byte>(writeBuffer), writeBuffer.Length);

                    if ((sslState = this.VerifyError(read)) > 0)
                    {
                        if (sslState == SslState.WANTREAD)
                        {
                            return SslState.NONE;
                        }

                        return sslState;
                    }

                    //advance buffer writer with the amount read
                    bufferWriter.Advance(read);
                } while ((pending = SSLWrapper.SSL_pending(this._sslHandle)) > 0);
            }

            return SslState.NONE;
        }

        public SslState WriteSsl
        (
            Span<byte> writableBuffer,
            out int totalWritten
        )
        {
            ReadOnlySpan<byte> readableBuffer = ReadOnlySpan<byte>.Empty;

            return this.WriteSsl
            (
                readableBuffer,
                writableBuffer,
                out _,
                out totalWritten
            );
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

            if (readableBuffer.Length < _MaxUnencryptedLength)
            {
                readBuf = readableBuffer;
            }
            else
            {
                readBuf = readableBuffer.Slice(readIndex, _MaxUnencryptedLength);
            }

            do
            {
                //allow to continue from previous write operation
                if(readBuf.Length > 0)
                {
                    //write unencrypted data into ssl
                    written = SSLWrapper.SSL_write(this._sslHandle, MemoryMarshal.GetReference<byte>(readBuf), readBuf.Length);

                    if ((sslState = this.VerifyError(written)) > 0)
                    {
                        totalRead = readIndex;
                        totalWritten = writeIndex;

                        //if (sslState == SslState.WANTREAD)
                        //{
                        //    return VerifyReadState(this._readHandle, this._sslHandle);
                        //}

                        return sslState;
                    }

                    readIndex += written;
                }

                //prepare write buffer
                if (writableBuffer.Length < writeIndex + _MaxEncryptedLength)
                {
                    writeBuf = writableBuffer.Slice(writeIndex);
                }
                else
                {
                    writeBuf = writableBuffer.Slice(writeIndex, _MaxEncryptedLength);
                }

                //read encrypted data
                sslState = this.ReadEncryptedIntoBuffer
                (
                    writeBuf,
                    out read
                );

                //increase write index
                writeIndex += read;

                //no more data can be written
                if (writeIndex == writableBuffer.Length)
                {
                    totalRead = readIndex;
                    totalWritten = writeIndex;
                    return sslState;
                }

                //prepare next read buffer
                if (readableBuffer.Length < readIndex + _MaxUnencryptedLength)
                {
                    readBuf = readableBuffer.Slice(readIndex);

                }
                else
                {
                    readBuf = readableBuffer.Slice(readIndex, _MaxUnencryptedLength);
                }
            } while (readBuf.Length > 0);

            totalRead = readIndex;
            totalWritten = writeIndex;
            return sslState;
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
            ReadOnlySpan<byte> span,
            IBufferWriter<byte> bufferWriter,
            out int totalRead
        )
        {
            ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

            totalRead = 0;

            if(span.IsEmpty)
            {
                return SslState.NONE;
            }

            SslState sslState;

            //write unencrypted data into ssl
            int written = SSLWrapper.SSL_write(this._sslHandle, in MemoryMarshal.GetReference<byte>(span), span.Length);

            if ((sslState = this.VerifyError(written)) > 0)
            {
                if (sslState == SslState.WANTREAD)
                {
                    return SslState.NONE;
                }

                return sslState;
            }

            totalRead = written;

            //then read the (encrypted) buffer into the bufferwriter
            this.WriteSslIntoBufferWriter(bufferWriter);

            return SslState.NONE;
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
            ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

            totalRead = sequence.Start;

            if(sequence.IsEmpty)
            {
                return SslState.NONE;
            }

            if (sequence.IsSingleSegment)
            {
                this.WriteSsl(sequence.FirstSpan, bufferWriter, out int read);
                totalRead = sequence.GetPosition(read);
                return SslState.NONE;
            }

            int written = 0, totalWritten = 0;
            ReadOnlySpan<byte> span;
            SslState sslState;

            //first write the complete (multi segment) (unencrypted) buffer
            foreach (ReadOnlyMemory<byte> memory in sequence)
            {
                if(memory.IsEmpty)
                {
                    continue;
                }

                //get the span
                span = memory.Span;

                //write encrypted data to the BIO
                written = SSLWrapper.SSL_write(this._sslHandle, in MemoryMarshal.GetReference<byte>(span), span.Length);

                if((sslState = this.VerifyError(written)) > 0)
                {
                    if (sslState == SslState.WANTREAD)
                    {
                        return SslState.NONE;
                    }

                    return sslState;
                }

                //encrease total bytes encrypted
                totalWritten += written;

                if(written < span.Length)
                {
                    break;
                }
            }

            totalRead = sequence.GetPosition(totalWritten);

            //then read the (encrypted) buffer into the bufferwriter
            this.WriteSslIntoBufferWriter(bufferWriter);

            return SslState.NONE;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static SslState VerifyWriteState
        (
            SafeBioHandle writeHandle
        )
        {
            if (CryptoWrapper.BIO_ctrl_pending(writeHandle) > 0)
            {
                return SslState.WANTWRITE;
            }
            else
            {
                return SslState.NONE;
            }
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
                return VerifyWriteState(this._writeHandle);
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

            return VerifyWriteState(this._writeHandle);
        }

        private void WriteSslIntoBufferWriter(IBufferWriter<byte> bufferWriter)
        {
            int written = 0, pending = 0;

            //check if any more data is pending to be written
            while ((pending = (int)CryptoWrapper.BIO_ctrl_pending(this._writeHandle)) > 0)
            {
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
        }

        /// <summary>
        /// Check if the current SSL context is in an erroneous state
        /// </summary>
        /// <param name="ret">The return value from a previous read/write operation on the ssl context</param>
        /// <returns>A user handleable <see cref="SslState"/></returns>
        /// <exception cref="ShutdownException">When a shutdown has already occured</exception>
        /// <exception cref="OpenSslException">When the SSL context is in an erroneous state</exception>
        private SslState VerifyError(int ret)
        {
            if(ret > 0)
            {
                return SslState.NONE;
            }

            //TODO: error handling incorrect
            int errorCode = SSLWrapper.SSL_get_error(this._sslHandle, ret);
            SslError error = (SslError)errorCode;

            return this.MapNativeError(error);
        }

        private SslState MapNativeError(SslError error)
        {
            switch (error)
            {
                
                case SslError.SSL_ERROR_SYSCALL:
                case SslError.SSL_ERROR_SSL:
                    //error of different kind happened, check the currents thread error queue
                    throw new OpenSslException();
                case SslError.SSL_ERROR_WANT_READ:
                case SslError.SSL_ERROR_WANT_WRITE:
                    return this.GetWriteBioState(error);
                case SslError.SSL_ERROR_ZERO_RETURN:
                case SslError.SSL_ERROR_NONE:
                default:
                    return SslState.NONE;
            }
        }

        private SslState MapNativeReadWriteError(SslError error)
        {
            switch (error)
            {
                case SslError.SSL_ERROR_WANT_READ:
                    return SslState.WANTREAD;
                case SslError.SSL_ERROR_WANT_WRITE:
                    return SslState.WANTWRITE;
                default:
                    throw new NotSupportedException($"Unsupported read/write error {error}");
            }
        }

        //as we're using non-blocking IO, the state of the underlying BIO needs to get checked
        private SslState GetWriteBioState(SslError error)
        {
            //always prioritize write request
            if(CryptoWrapper.BIO_ctrl_pending(this._writeHandle) > 0)
            {
                return SslState.WANTWRITE;
            }

            return this.MapNativeReadWriteError(error);
        }

        /// <summary>
        /// The SSL connection needs a write to continue.
        /// </summary>
        /// <param name="writeBuffer">The writable buffer</param>
        /// <param name="totalWritten">The total bytes written into <paramref name="writeBuffer"/></param>
        /// <returns>true if no more pending data is available</returns>
        /// <exception cref="OpenSslException"></exception>
        public SslState WritePending
        (
            Span<byte> writeBuffer,
            out int totalWritten
        )
        {
            return this.WriteSsl
            (
                writeBuffer,
                out totalWritten
            );

            //int read = 0;
            //SslError error;

            ////TODO: check if all has been read

            //if (CryptoWrapper.BIO_ctrl_pending(this._writeHandle) == 0)
            //{
            //    totalWritten = 0;
            //    return true;
            //}

            //if (writeBuffer.IsEmpty)
            //{
            //    totalWritten = 0;
            //    return false;
            //}

            ////read what needs to be sent to the other party
            //read = CryptoWrapper.BIO_read(this._writeHandle, ref MemoryMarshal.GetReference<byte>(writeBuffer), writeBuffer.Length);

            //if (read < 0)
            //{
            //    throw new OpenSslException();
            //}

            //totalWritten = read;

            //return CryptoWrapper.BIO_ctrl_pending(this._writeHandle) == 0;
        }

        /// <summary>
        /// The SSL connection needs a write to continue.
        /// </summary>
        /// <param name="bufferWriter">The writable buffer</param>
        /// <returns>true if no more pending data is available</returns>
        /// <exception cref="OpenSslException"></exception>
        public bool WritePending
        (
            IBufferWriter<byte> bufferWriter
        )
        {
            int read = 0, pending = 0, totalRead = 0;
            Span<byte> writeBuffer;

            while ((pending = (int)CryptoWrapper.BIO_ctrl_pending(this._writeHandle)) > 0)
            {
                //get a buffer from the writer pool
                writeBuffer = bufferWriter.GetSpan(pending);

                //read what needs to be sent to the other party
                read = CryptoWrapper.BIO_read(this._writeHandle, ref MemoryMarshal.GetReference<byte>(writeBuffer), writeBuffer.Length);

                if (read < 0)
                {
                    throw new OpenSslException();
                }

                bufferWriter.Advance(read);
                totalRead += read;
            }

            return pending == 0;
        }

        /// <summary>
        /// The SSL connection needs a read to continue.
        /// </summary>
        /// <param name="readableBuffer">The buffer containing the read data</param>
        /// <param name="totalRead">Total bytes read from the buffer</param>
        /// <returns>The next action or <see cref="SslState.NONE"/></returns>
        /// <exception cref="OpenSslException"></exception>
        public SslState ReadPending
        (
            ReadOnlySpan<byte> readableBuffer,
            out int totalRead
        )
        {
            return this.ReadSsl
            (
                readableBuffer,
                out totalRead
            );

            //int written = 0;

            //if (readableBuffer.IsEmpty)
            //{
            //    totalRead = 0;
            //    return;
            //}

            //written = CryptoWrapper.BIO_write(this._readHandle, in MemoryMarshal.GetReference<byte>(readableBuffer), readableBuffer.Length);

            //if (written < 0)
            //{
            //    throw new OpenSslException();
            //}

            //totalRead = written;
        }

        /// <summary>
        /// The SSL connection needs a read to continue.
        /// </summary>
        /// <param name="sequence">The buffer containing the read data</param>
        /// <param name="totalRead">Total bytes read from the buffer</param>
        /// <returns>The next action or <see cref="SslState.NONE"/></returns>
        /// <exception cref="OpenSslException"></exception>
        public void ReadPending
        (
            in ReadOnlySequence<byte> sequence,
            out SequencePosition totalRead
        )
        {
            SslError error;
            totalRead = sequence.Start;
            int written = 0, totalWritten = 0;
            ReadOnlySpan<byte> span;

            //if different action is required or the read buffer is empty
            //if ((error = (SslError)SSLWrapper.SSL_get_error(this._sslHandle, 0)) != SslError.SSL_ERROR_WANT_READ
            //    | sequence.IsEmpty)
            //{
            //    return this.TranslateError(error);
            //}

            if(sequence.IsEmpty)
            {
                return;
            }

            //single segment optimized path
            if (sequence.IsSingleSegment)
            {
                span = sequence.FirstSpan;
                written = CryptoWrapper.BIO_write(this._readHandle, in MemoryMarshal.GetReference<byte>(span), span.Length);

                if (written < 0)
                {
                    throw new OpenSslException();
                }

                totalWritten += written;

                totalRead = sequence.GetPosition(totalWritten);

                return;
            }

            ReadOnlySequence<byte>.Enumerator memoryEnumerator = sequence.GetEnumerator();
            ReadOnlyMemory<byte> memory;
            do
            {
                //get next memory in sequence
                if (!memoryEnumerator.MoveNext())
                {
                    //or exit loop
                    break;
                }

                memory = memoryEnumerator.Current;

                //write the next memory into the ssl buffer
                written = CryptoWrapper.BIO_write(this._readHandle, in MemoryMarshal.GetReference<byte>(memory.Span), memory.Length);

                if (written < 0)
                {
                    throw new OpenSslException();
                }

                totalWritten += written;
            } while ((error = (SslError)SSLWrapper.SSL_get_error(this._sslHandle, 0)) == SslError.SSL_ERROR_WANT_READ);

            totalRead = sequence.GetPosition(totalWritten);
        }

        /// <summary>
        /// Force a new handshake resuming the existing session
        /// </summary>
        public SslState Renegotiate()
        {
            ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

            int versionNumber = SSLWrapper.SSL_version(this._sslHandle);
            SslVersion version = (SslVersion)versionNumber;

            if(version == SslVersion.TLS1_3_VERSION)
            {
                SSLWrapper.SSL_key_update(this._sslHandle, 1);
            }
            else
            {
                SSLWrapper.SSL_renegotiate_abbreviated(this._sslHandle);
            }

            if(this.DoHandshake(out SslState state))
            {
                throw new InvalidOperationException("Handshake should not have completed");
            }

            return state;
        }

        public void Renegotiate
        (
            IBufferWriter<byte> bufferWriter
        )
        {
            ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

            int versionNumber = SSLWrapper.SSL_version(this._sslHandle);
            SslVersion version = (SslVersion)versionNumber;

            if (version == SslVersion.TLS1_3_VERSION)
            {
                SSLWrapper.SSL_key_update(this._sslHandle, 1);
            }
            else
            {
                SSLWrapper.SSL_renegotiate_abbreviated(this._sslHandle);
            }

            if (this.DoHandshake(out _))
            {
                throw new InvalidOperationException("Handshake should not have completed");
            }

            this.WritePending(bufferWriter);
        }

        //helper functions for testing
#if DEBUG
        public SslState CheckState
        (
            Span<byte> writeBuffer
        )
        {
            int read = SSLWrapper.SSL_peek(this._sslHandle, ref MemoryMarshal.GetReference<byte>(writeBuffer), writeBuffer.Length);
            return this.VerifyError(read);
        }

        public bool IsRenegotiatePending
        {
            get
            {
                ThrowInvalidOperationException_HandshakeNotCompleted(this._handshakeCompleted);

                return SSLWrapper.SSL_renegotiate_pending(this._sslHandle) == 1;
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
            catch(Exception)
            { }

            try
            {
                this._readHandle?.Dispose();
            }
            catch(Exception)
            { }

            try
            {
                this._writeHandle?.Dispose();
            }
            catch(Exception)
            { }

            try
            {
                this._sslContext?._sslContextHandle.DangerousRelease();
            }
            catch(Exception)
            { }

            if (!isDisposing)
            {
                return;
            }

            GC.SuppressFinalize(this);
        }
    }
}
