﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Reflection;

using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.SSL.Exceptions;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using OpenSSL.Core.Error;
using OpenSSL.Core.Collections;
using OpenSSL.Core.SSL.Pipelines;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.SSL
{
    public partial class SocketConnection
    {
        private NewSessionCallback s_NewSessionCallbackCallback;

        #region Authentication wrapper methods (should be called only once)
        public Task AuthenticateAsClientAsync()
        {
            try
            {
                this.CreateContexthandle(false, null, null, null);
                return this.DoHandshake(false);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        public Task AuthenticateAsClientAsync(SslStrength sslStrength)
        {
            try
            {
                this.CreateContexthandle(false, sslStrength, null, null);
                return this.DoHandshake(false);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        public Task AuthenticateAsClientAsync(SslProtocol sslProtocol)
        {
            try
            {
                this.CreateContexthandle(false, null, sslProtocol, null);
                return this.DoHandshake(false);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        public Task AuthenticateAsClientAsync(IEnumerable<string> allowedCiphers)
        {
            try
            {
                this.CreateContexthandle(false, null, null, allowedCiphers);
                return this.DoHandshake(false);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        public Task AuthenticateAsClientAsync(SslProtocol sslProtocol, IEnumerable<string> allowedCiphers)
        {
            try
            {
                this.CreateContexthandle(false, null, sslProtocol, allowedCiphers);
                return this.DoHandshake(false);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        /// <summary>
        /// Authenticate as client and validate the remote certificate using <paramref name="remoteValidation"/>
        /// </summary>
        /// <param name="remoteValidation">The validation delegate to verify the server certificate</param>
        public Task AuthenticateAsClientAsync(RemoteCertificateValidationHandler remoteValidation, SslProtocol? sslProtocol = null)
        {
            try
            {
                this.CreateContexthandle(false, null, sslProtocol, null);
                this.SetRemoteValidation(VerifyMode.SSL_VERIFY_PEER, remoteValidation);
                return this.DoHandshake(false);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        /// <summary>
        /// Authenticate as client and validate the remote certificate using the certificates in <paramref name="remoteCA"/>
        /// </summary>
        /// <param name="remoteCA">The certificate to verify the remote certificate with</param>
        /// <returns></returns>
        public Task AuthenticateAsClientAsync(IEnumerable<X509Certificate> remoteCA, SslProtocol? sslProtocol = null)
        {
            try
            {
                this.CreateContexthandle(false, null, sslProtocol, null);

                //add the certificates to the trusted store
                foreach (X509Certificate cert in remoteCA)
                    this.CertificateStore.AddCertificate(cert);

                //enable internal peer certificate validation
                SSLWrapper.SSL_CTX_set_verify(this.SslContextWrapper.SslContextHandle, (int)VerifyMode.SSL_VERIFY_PEER, null);

                return this.DoHandshake(false);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        /// <summary>
        /// Authenticate as client and pick a client certificate using <paramref name="clientCertificateCallback"/>
        /// </summary>
        /// <param name="clientCertificateCallback">The client certificate callback to use</param>
        /// <returns></returns>
        public Task AuthenticateAsClientAsync(ClientCertificateCallbackHandler clientCertificateCallback, SslProtocol? sslProtocol = null)
        {
            try
            {
                this.CreateContexthandle(false, null, sslProtocol, null);
                this.ClientCertificateCallbackHandler = clientCertificateCallback;
                return this.DoHandshake(false);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        /// <summary>
        /// Authenticate as client using a Client Certificate and Key
        /// </summary>
        /// <param name="clientCertificate">The client Certificate to use</param>
        /// <param name="clientKey">The client key to use</param>
        public Task AuthenticateAsClientAsync(X509Certificate clientCertificate, PrivateKey clientKey, SslProtocol? sslProtocol = null)
        {
            try
            {
                this.CreateContexthandle(false, null, sslProtocol, null);
                this.SetLocalCertificate(clientCertificate, clientKey);
                return this.DoHandshake(false);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey)
        {
            try
            {
                if (this.CreateContexthandle(true, null, null, null))
                    this.SetLocalCertificate(serverCertificate, privateKey);
                return this.DoHandshake(true);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        /// <summary>
        /// Authenticate as server with Client Certificate Verification
        /// </summary>
        /// <param name="serverCertificate">The server certificate to use</param>
        /// <param name="privateKey">The server key to use</param>
        /// <param name="clientCA">The Client Certificate CA to use for verification</param>
        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, IEnumerable<X509Certificate> clientCA)
        {
            try
            {
                if (this.CreateContexthandle(true, null, null, null))
                {
                    this.SetLocalCertificate(serverCertificate, privateKey);

                    //add client CA to allowed name list and add to trusted store
                    foreach (X509Certificate cert in clientCA)
                        this.AddClientCertificateCA(cert);

                    //enable internal client certificate validation
                    SSLWrapper.SSL_CTX_set_verify(this.SslContextWrapper.SslContextHandle, (int)VerifyMode.SSL_VERIFY_PEER, null);
                }
                return this.DoHandshake(true);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        /// <summary>
        /// Authenticate as server and verify the remote certificate (client certificate) using <paramref name="remoteValidation"/>
        /// </summary>
        /// <param name="serverCertificate">The server certificate to use</param>
        /// <param name="privateKey">The server key to use</param>
        /// <param name="remoteValidation">The validation delegate to verify the client certificate</param>
        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, RemoteCertificateValidationHandler remoteValidation)
        {
            try
            {
                if (this.CreateContexthandle(true, null, null, null))
                {
                    this.SetLocalCertificate(serverCertificate, privateKey);
                    this.SetRemoteValidation(VerifyMode.SSL_VERIFY_PEER, remoteValidation);
                }
                return this.DoHandshake(true);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, SslStrength sslStrength)
        {
            try
            {
                if (this.CreateContexthandle(true, sslStrength, null, null))
                    this.SetLocalCertificate(serverCertificate, privateKey);
                return this.DoHandshake(true);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, SslProtocol sslProtocol)
        {
            try
            {
                if (this.CreateContexthandle(true, null, sslProtocol, null))
                    this.SetLocalCertificate(serverCertificate, privateKey);
                return this.DoHandshake(true);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, IEnumerable<string> allowedCiphers)
        {
            try
            {
                if (this.CreateContexthandle(true, null, null, allowedCiphers))
                    this.SetLocalCertificate(serverCertificate, privateKey);
                return this.DoHandshake(true);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }

        public Task AuthenticateAsServerAsync(X509Certificate serverCertificate, PrivateKey privateKey, SslProtocol sslProtocol, IEnumerable<string> allowedCiphers)
        {
            try
            {
                if (this.CreateContexthandle(true, null, sslProtocol, allowedCiphers))
                    this.SetLocalCertificate(serverCertificate, privateKey);
                return this.DoHandshake(true);
            }
            catch (Exception)
            {
                this.SSLCleanup();
                throw;
            }
        }
        #endregion

        #region OpenSSL (reusable) SSL_CTX initialization
        //set (reusable) context options
        //all SSL object use these
        private bool CreateContexthandle(bool isServer, SslStrength? sslStrength, SslProtocol? sslProtocol, IEnumerable<string> ciphers)
        {
            if (this.SslContextWrapper is null)
                this.SslContextWrapper = new SslContextRefWrapper();

            if (!(this.SslContextWrapper.SslContextHandle is null))
                return false;

            if (Interop.Version.Library < Interop.Version.MinimumOpenSslTLS13Version
                && !(sslProtocol is null)
                && (sslProtocol & SslProtocol.Tls13) == SslProtocol.Tls13)
                throw new InvalidOperationException("Currently used OpenSSL library doesn't support TLS 1.3, atleast version 1.1.1 is needed.");

            if (isServer)
                this.SslContextWrapper.SslContextHandle = SSLWrapper.SSL_CTX_new(SafeSslMethodHandle.DefaultServerMethod);
            else
                this.SslContextWrapper.SslContextHandle = SSLWrapper.SSL_CTX_new(SafeSslMethodHandle.DefaultClientMethod);

            SSLWrapper.SSL_CTX_ctrl(this.SslContextWrapper.SslContextHandle, Native.SSL_CTRL_MODE, (int)SslMode.SSL_MODE_ENABLE_PARTIAL_WRITE, IntPtr.Zero);

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

                if (Interop.Version.Library >= Interop.Version.MinimumOpenSslTLS13Version 
                    && (sslProtocol & SslProtocol.Tls13) != SslProtocol.Tls13)
                    protocolOptions |= SslOptions.SSL_OP_NO_TLSv1_3;
            }

            SSLWrapper.SSL_CTX_set_options(this.SslContextWrapper.SslContextHandle, (long)protocolOptions);

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

                        if(!(sslProtocol is null)
                            && (sslProtocol & SslProtocol.Tls13) == SslProtocol.Tls13)
                            SSLWrapper.SSL_CTX_set_ciphersuites(this.SslContextWrapper.SslContextHandle, bSpan.GetPinnableReference());
                        else
                            SSLWrapper.SSL_CTX_set_cipher_list(this.SslContextWrapper.SslContextHandle, bSpan.GetPinnableReference());
                    }
                }
            }

            if(!(sslStrength is null))
                SSLWrapper.SSL_CTX_set_security_level(this.SslContextWrapper.SslContextHandle, (int)sslStrength);

            if(this.s_NewSessionCallbackCallback is null)
            {
                this.s_NewSessionCallbackCallback = this.NewSessionCallback;
                SSLWrapper.SSL_CTX_ctrl(this.SslContextWrapper.SslContextHandle,
                                             Native.SSL_CTRL_SET_SESS_CACHE_MODE,
                                             (int)Native.SSL_SESS_CACHE_CLIENT | Native.SSL_SESS_CACHE_NO_INTERNAL,
                                             IntPtr.Zero);
                SSLWrapper.SSL_CTX_sess_set_new_cb(this.SslContextWrapper.SslContextHandle, this.s_NewSessionCallbackCallback);
            }

            return true;
        }

        private void SetLocalCertificate(X509Certificate serverCertificate, PrivateKey privateKey)
        {
            if (!serverCertificate.VerifyPrivateKey(privateKey))
                throw new InvalidOperationException("Public and private key do not match");

            SSLWrapper.SSL_CTX_use_certificate(this.SslContextWrapper.SslContextHandle, serverCertificate.X509Wrapper.Handle);
            SSLWrapper.SSL_CTX_use_PrivateKey(this.SslContextWrapper.SslContextHandle, privateKey.KeyWrapper.Handle);
        }
        #endregion

        private int NewSessionCallback(IntPtr sslPtr, IntPtr sessPtr)
        {
            Type sslType = null;
            ConstructorInfo sslCtor = sslType.GetConstructor(new Type[] { typeof(IntPtr), typeof(bool), typeof(bool) });
            object newSslObj = sslCtor.Invoke(new object[] { sslPtr, false, false });
            SafeSslHandle ssl = newSslObj as SafeSslHandle;

            if (!(this.SessionHandle is null) || SSLWrapper.SSL_session_reused(ssl) == 1)
                return 0;

            Type sessType = null;
            ConstructorInfo sessCtor = sessType.GetConstructor(new Type[] { typeof(IntPtr), typeof(bool), typeof(bool) });
            object newSessObj = sessCtor.Invoke(new object[] { sessPtr, false, false });

            this.SessionHandle = newSessObj as SafeSslSessionHandle;

            //return 1 so that the session will not get freed again
            return 1;
        }

        //TOOD: ensure socket pipe is empty
        private async Task DoHandshake(bool isServer)
        {
            if (!this.Socket.Connected)
                throw new InvalidOperationException("Socket not connected");

            if (this.encryptionEnabled)
                return;

            if (!this.TrySetSslState(SslState.None, SslState.Handshake))
                throw new InvalidOperationException("Could not set correct connection state");

            //clean up any previous ssl remnants
            this.SSLCleanup();

            //create new native handles
            this.readHandle = CryptoWrapper.BIO_new(CryptoWrapper.BIO_s_mem());
            this.writeHandle = CryptoWrapper.BIO_new(CryptoWrapper.BIO_s_mem());

            this.sslHandle = SSLWrapper.SSL_new(this.SslContextWrapper.SslContextHandle);
            SSLWrapper.SSL_set_bio(this.sslHandle, this.readHandle, this.writeHandle);

            //add references for correct disposal
            this.readHandle.AddRef();
            this.writeHandle.AddRef();

            //set correct connection endpoint options
            if (isServer)
                SSLWrapper.SSL_set_accept_state(this.sslHandle);
            else
                SSLWrapper.SSL_set_connect_state(this.sslHandle);

            //reuse session if any was set in other connection/before reset
            if (!(this.SessionHandle is null))
                SSLWrapper.SSL_set_session(this.sslHandle, this.SessionHandle);

            try
            {
                await this.DoHandshake().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                this.TrySetSslState(SslState.Handshake, SslState.None);
                throw new SslHandshakeException(ex);
            }
        }

        //TODO: renegotiation
        private async Task DoHandshake()
        {
            int ret_code, result;
            ValueTask<FlushResult> flushResult;
            
            //TODO: wait on all data sent
            this._sendToSocket.StartInterrupt(true);
            this._receiveFromSocket.StartInterrupt(true);

            try
            {
                do
                {
                    //get next action from OpenSSL wrapper
                    ret_code = SSLWrapper.SSL_do_handshake(this.sslHandle);
                    if ((result = SSLWrapper.SSL_get_error(this.sslHandle, ret_code)) == (int)SslError.SSL_ERROR_SSL)
                    {
                        VerifyResult verifyResult;
                        if ((verifyResult = (VerifyResult)SSLWrapper.SSL_get_verify_result(this.sslHandle)) > VerifyResult.X509_V_OK)
                            throw new OpenSslException(new VerifyError(verifyResult));

                        throw new OpenSslException();
                    }

                    flushResult = this.WritePending();
                    if (!flushResult.IsCompleted)
                        await flushResult.ConfigureAwait(false);

                    await this.ReadPending((SslError)result).ConfigureAwait(false);
                } while (SSLWrapper.SSL_is_init_finished(this.sslHandle) != 1);

                //set state to established
                if (!this.TrySetSslState(SslState.Handshake, SslState.Established))
                    throw new InvalidOperationException("Could not set correct connection state");
            }
            finally
            {
                this._sendToSocket.CompleteInterrupt(true);
                this._receiveFromSocket.CompleteInterrupt(true);
            }
        }
    }
}
