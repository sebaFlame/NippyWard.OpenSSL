using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;
using System.IO.Pipelines;

using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.SSL.Exceptions;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using OpenSSL.Core.Error;

namespace OpenSSL.Core.SSL
{
    public partial class SocketConnection
    {
        #region Authentication wrapper methods (should be called only once)
        public Task AuthenticateAsClientAsync()
        {
            this.CreateContexthandle(false, null, null, null);
            return this.DoHandshake(false);
        }

        public Task AuthenticateAsClientAsync(SslStrength sslStrength)
        {
            this.CreateContexthandle(false, sslStrength, null, null);
            return this.DoHandshake(false);
        }

        public Task AuthenticateAsClientAsync(SslProtocol sslProtocol)
        {
            this.CreateContexthandle(false, null, sslProtocol, null);
            return this.DoHandshake(false);
        }

        public Task AuthenticateAsClientAsync(IEnumerable<string> allowedCiphers)
        {
            this.CreateContexthandle(false, null, null, allowedCiphers);
            return this.DoHandshake(false);
        }

        public Task AuthenticateAsClientAsync(SslProtocol sslProtocol, IEnumerable<string> allowedCiphers)
        {
            this.CreateContexthandle(false, null, sslProtocol, allowedCiphers);
            return this.DoHandshake(false);
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey)
        {
            if (this.CreateContexthandle(true, null, null, null))
                this.SetServerCertificate(serverCertificate, privateKey);
            return this.DoHandshake(true);
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, SslStrength sslStrength)
        {
            if(this.CreateContexthandle(true, sslStrength, null, null))
                this.SetServerCertificate(serverCertificate, privateKey);
            return this.DoHandshake(true);
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, SslProtocol sslProtocol)
        {
            if(this.CreateContexthandle(true, null, sslProtocol, null))
                this.SetServerCertificate(serverCertificate, privateKey);
            return this.DoHandshake(true);
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, IEnumerable<string> allowedCiphers)
        {
            if(this.CreateContexthandle(true, null, null, allowedCiphers))
                this.SetServerCertificate(serverCertificate, privateKey);
            return this.DoHandshake(true);
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, SslProtocol sslProtocol, IEnumerable<string> allowedCiphers)
        {
            if(this.CreateContexthandle(true, null, sslProtocol, allowedCiphers))
                this.SetServerCertificate(serverCertificate, privateKey);
            return this.DoHandshake(true);
        }
        #endregion

        #region OpenSSL (reusable) SSL_CTX initialization
        //set (reusable) context options
        //all SSL object use these
        private bool CreateContexthandle(bool isServer, SslStrength? sslStrength, SslProtocol? sslProtocol, IEnumerable<string> ciphers)
        {
            if (!(this.sslContextHandle is null))
                return false;

            if(isServer)
                this.sslContextHandle = this.SSLWrapper.SSL_CTX_new(SafeSslMethodHandle.DefaultServerMethod);
            else
                this.sslContextHandle = this.SSLWrapper.SSL_CTX_new(SafeSslMethodHandle.DefaultCientMethod);

            this.SSLWrapper.SSL_CTX_ctrl(this.sslContextHandle, Native.SSL_CTRL_MODE, (int)SslMode.SSL_MODE_ENABLE_PARTIAL_WRITE, IntPtr.Zero);

            SslOptions protocolOptions = SslOptions.SSL_OP_ALL;
            if(!(sslProtocol is null))
            {
                if ((sslProtocol & SslProtocol.Ssl3) != SslProtocol.Ssl3)
                    protocolOptions |= SslOptions.SSL_OP_NO_SSLv3;

                if ((sslProtocol & SslProtocol.Tls) != SslProtocol.Tls)
                    protocolOptions |= SslOptions.SSL_OP_NO_TLSv1;

                if ((sslProtocol & SslProtocol.Tls11) != SslProtocol.Tls11)
                    protocolOptions |= SslOptions.SSL_OP_NO_TLSv1_1;

                if ((sslProtocol & SslProtocol.Tls12) != SslProtocol.Tls12)
                    protocolOptions |= SslOptions.SSL_OP_NO_TLSv1_2;

                //TODO: TLS1.3
            }

            this.SSLWrapper.SSL_CTX_set_options(this.sslContextHandle, (long)protocolOptions);

            if(!(ciphers is null))
            {
                foreach(string cipher in ciphers)
                {
                    if (!SupportedCiphers.Contains(cipher))
                        throw new InvalidOperationException($"Unknown cipher: {cipher}");
                }

                string allowedCiphers = string.Join(":", ciphers);
                unsafe
                {
                    ReadOnlySpan<char> chSpan = allowedCiphers.AsSpan();
                    fixed(char* ch = chSpan)
                    {
                        int count = Encoding.ASCII.GetEncoder().GetByteCount(ch, chSpan.Length, false);
                        byte* b = stackalloc byte[count];
                        Encoding.ASCII.GetEncoder().GetBytes(ch, chSpan.Length, b, count, true);
                        ReadOnlySpan<byte> bSpan = new ReadOnlySpan<byte>(b, count);
                        this.SSLWrapper.SSL_CTX_set_cipher_list(this.sslContextHandle, bSpan.GetPinnableReference());
                    }
                }
            }

            if(!(sslStrength is null))
                this.SSLWrapper.SSL_CTX_set_security_level(this.sslContextHandle, (int)sslStrength);

            return true;
        }

        private void SetServerCertificate(X509Certificate serverCertificate, PrivateKey privateKey)
        {
            if (!serverCertificate.VerifyPrivateKey(privateKey))
                throw new InvalidOperationException("Public and private key do not match");

            this.SSLWrapper.SSL_CTX_use_certificate(this.sslContextHandle, serverCertificate.X509Handle);
            this.SSLWrapper.SSL_CTX_use_PrivateKey(this.sslContextHandle, privateKey.KeyHandle);
        }
        #endregion

        //TOOD: ensure socket pipe is empty
        private async Task DoHandshake(bool isServer)
        {
            if (this.encryptionEnabled)
                return;

            //TODO: throw exception
            if (!this.TrySetSslState(SslState.None, SslState.Handshake))
                return;

            //clean up any previous ssl remnants
            this.SSLCleanup();

            //create new native handles
            this.readHandle = this.CryptoWrapper.BIO_new(this.CryptoWrapper.BIO_s_mem());
            this.writeHandle = this.CryptoWrapper.BIO_new(this.CryptoWrapper.BIO_s_mem());

            this.sslHandle = this.SSLWrapper.SSL_new(this.sslContextHandle);
            this.SSLWrapper.SSL_set_bio(this.sslHandle, this.readHandle, this.writeHandle);

            //set correct connection endpoint options
            if (isServer)
                this.SSLWrapper.SSL_set_accept_state(this.sslHandle);
            else
                this.SSLWrapper.SSL_set_connect_state(this.sslHandle);

            //reuse session if any was set in other connection/before reset
            if (!(this.sessionHandle is null))
                this.SSLWrapper.SSL_set_session(this.sslHandle, this.sessionHandle);

            try
            {
                await this.DoHandshake().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new SslHandshakeException(ex);
            }
        }

        private async Task DoHandshake()
        {
            int ret_code, result;
            ValueTask<FlushResult> flushResult;

            this._receiveFromSocket.Reader.CancelPendingRead();

            do
            {
                //get next action from OpenSSL wrapper
                ret_code = this.SSLWrapper.SSL_do_handshake(this.sslHandle);
                if ((result = this.SSLWrapper.SSL_get_error(this.sslHandle, ret_code)) == (int)SslError.SSL_ERROR_SSL)
                    throw new OpenSslException();

                flushResult = this.WritePending();
                if (!flushResult.IsCompleted)
                    await flushResult.ConfigureAwait(false);

                await this.ReadPending((SslError)result).ConfigureAwait(false);
            } while (this.SSLWrapper.SSL_is_init_finished(this.sslHandle) != 1);

            //save current session if it's a new one
            //TODO: renegotiation
            if (this.sessionHandle is null || this.SSLWrapper.SSL_session_reused(this.sslHandle) == 0)
                this.sessionHandle = this.SSLWrapper.SSL_get_session(this.sslHandle);

            //set state to established
            this.TrySetSslState(SslState.Handshake, SslState.Established);

            //continue after state interruption
            this._socketReader.CompleteInterruption();
            this._socketWriter.CompleteInterruption();
        }
    }
}
