// Copyright (c) 2009 Ben Henderson
// Copyright (c) 2012 Frank Laub
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Buffers;
using System.Security.Cryptography;

using Xunit;
using Xunit.Abstractions;

using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.SSL;

namespace OpenSSL.Core.Tests
{
    public class TestSSL : TestBase
    {
        private SslTestContext _sslTestContext;
        private static byte[] _ClientMessage = Encoding.ASCII.GetBytes("This is a message from the client");
        private static byte[] _ServerMessage = Encoding.ASCII.GetBytes("This is a message from the server");

        private X509Certificate ServerCertificate => this._sslTestContext.ServerCertificate;
        private PrivateKey ServerKey => this.ServerCertificate.PublicKey;

        private X509Certificate ClientCertificate => this._sslTestContext.ClientCertificate;
        private PrivateKey ClientKey => this.ClientCertificate.PublicKey;

        private X509Certificate CACertificate => this._sslTestContext.CACertificate;

        private const int _BufferSize = 16383;
        private byte[] _serverReadBuffer;
        private byte[] _serverWriteBuffer;
        private byte[] _clientReadBuffer;
        private byte[] _clientWriteBuffer;

        public TestSSL(ITestOutputHelper outputHelper)
            : base(outputHelper)
        {
            this._sslTestContext = new SslTestContext();

            this._serverReadBuffer = ArrayPool<byte>.Shared.Rent(_BufferSize);
            this._serverWriteBuffer = ArrayPool<byte>.Shared.Rent(_BufferSize);
            this._clientReadBuffer = ArrayPool<byte>.Shared.Rent(_BufferSize);
            this._clientWriteBuffer = ArrayPool<byte>.Shared.Rent(_BufferSize);
        }

        protected override void Dispose(bool disposing)
        {
            ArrayPool<byte>.Shared.Return(this._serverReadBuffer);
            ArrayPool<byte>.Shared.Return(this._serverWriteBuffer);
            ArrayPool<byte>.Shared.Return(this._clientReadBuffer);
            ArrayPool<byte>.Shared.Return(this._clientWriteBuffer);

            this._sslTestContext.Dispose();
        }

        private static void DoSynchronousHandshake
        (
            Ssl serverContext,
            byte[] serverWriteBuffer,
            byte[] serverReadBuffer,
            Ssl clientContext,
            byte[] clientWriteBuffer,
            byte[] clientReadBuffer
        )
        {
            SslState clientState, serverState;
            int clientRead, serverRead, clientWritten, serverWritten;

            Assert.False(serverContext.DoHandshake(out serverState));
            Assert.NotEqual(SslState.NONE, serverState);

            Assert.False(clientContext.DoHandshake(out clientState));
            Assert.NotEqual(SslState.NONE, clientState);

            do
            {
                if (clientState == SslState.WANTWRITE)
                {
                    //get the client buffer
                    clientState = clientContext.WritePending(clientWriteBuffer, out clientWritten);

                    //and write it to the server
                    Array.Copy(clientWriteBuffer, 0, serverReadBuffer, 0, clientWritten);
                    serverState = serverContext.ReadPending
                    (
                        new ReadOnlySpan<byte>(serverReadBuffer, 0, clientWritten),
                        out serverRead
                    );

                    //verify write was complete
                    Assert.Equal(clientWritten, serverRead);
                }

                if (serverState == SslState.WANTWRITE)
                {
                    //get the server buffer
                    serverState = serverContext.WritePending(serverWriteBuffer, out serverWritten);

                    //and write it to the client
                    Array.Copy(serverWriteBuffer, 0, clientReadBuffer, 0, serverWritten);
                    clientState = clientContext.ReadPending
                    (
                        new ReadOnlySpan<byte>(clientReadBuffer, 0, serverWritten),
                        out clientRead
                    );

                    //verify write was complete
                    Assert.Equal(serverWritten, clientRead);
                }
            } while (clientState == SslState.WANTWRITE
                || serverState == SslState.WANTWRITE);

            Assert.True(serverContext.DoHandshake(out serverState));
            Assert.Equal(SslState.NONE, serverState);

            Assert.True(clientContext.DoHandshake(out clientState));
            Assert.Equal(SslState.NONE, clientState);
        }

        private static void DoSynchronousShutdown
        (
            Ssl serverContext,
            byte[] serverWriteBuffer,
            byte[] serverReadBuffer,
            Ssl clientContext,
            byte[] clientWriteBuffer,
            byte[] clientReadBuffer
        )
        {
            SslState clientState, serverState;
            int clientRead, serverRead, clientWritten, serverWritten;

            Assert.False(serverContext.DoShutdown(out serverState));
            Assert.NotEqual(SslState.NONE, serverState);

            Assert.False(clientContext.DoShutdown(out clientState));
            Assert.NotEqual(SslState.NONE, clientState);

            //make sure you ALWAYS read both
            do
            {
                if (clientState == SslState.WANTWRITE)
                {
                    //get the client buffer
                    clientState = clientContext.WritePending(clientWriteBuffer, out clientWritten);

                    //and write it to the server
                    Array.Copy(clientWriteBuffer, 0, serverReadBuffer, 0, clientWritten);
                    serverContext.ReadPending
                    (
                        new ReadOnlySpan<byte>(serverReadBuffer, 0, clientWritten),
                        out serverRead
                    );

                    //verify write was complete
                    Assert.Equal(clientWritten, serverRead);
                }

                if (serverState == SslState.WANTWRITE)
                {
                    //get the server buffer
                    serverState = serverContext.WritePending(serverWriteBuffer, out serverWritten);

                    //and write it to the client
                    Array.Copy(serverWriteBuffer, 0, clientReadBuffer, 0, serverWritten);
                    clientContext.ReadPending
                    (
                        new ReadOnlySpan<byte>(clientReadBuffer, 0, serverWritten),
                        out clientRead
                    );

                    //verify write was complete
                    Assert.Equal(serverWritten, clientRead);
                }
            } while (clientState == SslState.WANTWRITE
                || serverState == SslState.WANTWRITE);

            Assert.True(serverContext.DoShutdown(out serverState));
            Assert.Equal(SslState.NONE, serverState);

            Assert.True(clientContext.DoShutdown(out clientState));
            Assert.Equal(SslState.NONE, clientState);
        }

        //the tests using this function are mostly used to test the
        //coherence between ReadSsl/WriteSsl and SslState.WANTREAD/SslState.WANTWRITE
        private static void DoSynchrounousRenegotiate
        (
            Ssl client1,
            byte[] client1WriteBuffer,
            byte[] client1ReadBuffer,
            Ssl client2,
            byte[] client2WriteBuffer,
            byte[] client2ReadBuffer
        )
        {
            SslState client1State = SslState.NONE, client2State = SslState.NONE;
            int client2Read, client1Read, client2Written, client1Written;

            //force new handshake with a writable buffer
            client1State = client1.Renegotiate();

            //verify it needs a write
            Assert.Equal(SslState.WANTWRITE, client1State);
            client1State = client1.WritePending(client1WriteBuffer, out client1Written);

            //and write it to the client
            //do a regular (!) read on the client (this is after initial handshake)
            Array.Copy(client1WriteBuffer, 0, client2ReadBuffer, 0, client1Written);
            client2State = client2.ReadSsl
            (
                new ReadOnlySpan<byte>(client2ReadBuffer, 0, client1Written),
                client2WriteBuffer,
                out client2Read,
                out client2Written
            );

            //verify write was complete
            Assert.Equal(client1Written, client2Read);

            //and nothing got decrypted
            Assert.Equal(0, client2Written);

            while (client1State == SslState.WANTWRITE
                || client2State == SslState.WANTWRITE)
            {
                if (client1State == SslState.WANTWRITE)
                {
                    //get the renegotiation buffer form the client
                    client1State = client1.WritePending
                    (
                        client1WriteBuffer,
                        out client1Written
                    );

                    //and read it into to the next client
                    Array.Copy(client1WriteBuffer, 0, client2ReadBuffer, 0, client1Written);
                    client2State = client2.ReadSsl
                    (
                        new ReadOnlySpan<byte>(client2ReadBuffer, 0, client1Written),
                        client2WriteBuffer,
                        out client2Read,
                        out client2Written
                    );

                    //verify write was complete
                    Assert.Equal(client1Written, client2Read);

                    //and nothing got decrypted
                    Assert.Equal(0, client2Written);
                }

                if (client2State == SslState.WANTWRITE)
                {
                    //get the renegotiation buffer form the client
                    client2State = client2.WritePending
                    (
                        client2WriteBuffer,
                        out client2Written
                    );

                    //and read it into to the next client
                    Array.Copy(client2WriteBuffer, 0, client1ReadBuffer, 0, client2Written);
                    client1State = client1.ReadSsl
                    (
                        new ReadOnlySpan<byte>(client1ReadBuffer, 0, client2Written),
                        client1WriteBuffer,
                        out client1Read,
                        out client1Written
                    );

                    //verify write was complete
                    Assert.Equal(client2Written, client1Read);

                    //and nothing got decrypted
                    Assert.Equal(0, client1Written);
                }
            }

#if DEBUG
            //only check these when using TLS1.2
            Assert.False(client1.IsRenegotiatePending);
            Assert.False(client2.IsRenegotiatePending);
#endif
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestHandshake(SslProtocol sslProtocol)
        {
            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );

            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol
            );

            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            clientContext.Dispose();
            serverContext.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestShutDown(SslProtocol sslProtocol)
        {
            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestData(SslProtocol sslProtocol)
        {
            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            SslState clientState, serverState;
            int totalRead, totalWritten;

            //send data from server
            serverState = serverContext.WriteSsl
            (
                _ServerMessage,
                this._serverWriteBuffer,
                out totalRead,
                out totalWritten
            );

            Assert.Equal(_ServerMessage.Length, totalRead);

            //verify no further action needs to be taken
            Assert.Equal(SslState.NONE, serverState);

            //Read data on client
            Array.Copy(this._serverWriteBuffer, 0, this._clientReadBuffer, 0, totalWritten);
            clientState = clientContext.ReadSsl
            (
                new ReadOnlySpan<byte>(this._clientReadBuffer, 0, totalWritten),
                this._clientWriteBuffer,
                out totalRead,
                out totalWritten
            );

            //verify no further action needs to be taken
            Assert.Equal(SslState.NONE, clientState);

            //verify read data
            Assert.True
            (
                new ReadOnlySpan<byte>(_ServerMessage)
                    .SequenceEqual(new ReadOnlySpan<byte>(this._clientWriteBuffer, 0, totalWritten))
            );

            //send data from client
            clientState = clientContext.WriteSsl
            (
                _ClientMessage,
                this._clientWriteBuffer,
                out totalRead,
                out totalWritten
            );

            //verify no further action needs to be taken
            Assert.Equal(SslState.NONE, clientState);

            Assert.Equal(_ClientMessage.Length, totalRead);

            //read data on server
            Array.Copy(this._clientWriteBuffer, 0, this._serverReadBuffer, 0, totalWritten);
            serverState = serverContext.ReadSsl
            (
                new ReadOnlySpan<byte>(this._serverReadBuffer, 0, totalWritten),
                this._serverWriteBuffer,
                out totalRead,
                out totalWritten
            );

            //verify no further action needs to be taken
            Assert.Equal(SslState.NONE, serverState);

            //verify read data
            Assert.True
            (
                new ReadOnlySpan<byte>(_ClientMessage)
                    .SequenceEqual(new ReadOnlySpan<byte>(this._serverWriteBuffer, 0, totalWritten))
            );

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestServerRenegotiate(SslProtocol sslProtocol)
        {
            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            DoSynchrounousRenegotiate
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestClientRenegotiate(SslProtocol sslProtocol)
        {
            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            DoSynchrounousRenegotiate
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestSessionReuse(SslProtocol sslProtocol)
        {
            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            if (sslProtocol == SslProtocol.Tls13)
            {
                //force session generation (needed by TLS1.3)
                //session only gets generated by the next data write
                SslState clientState, serverState;
                int totalRead, totalWritten;

                //send data from server
                serverState = serverContext.WriteSsl
                (
                    _ServerMessage,
                    this._serverWriteBuffer,
                    out totalRead,
                    out totalWritten
                );

                Assert.Equal(_ServerMessage.Length, totalRead);

                //verify no further action needs to be taken
                Assert.Equal(SslState.NONE, serverState);

                //Read data on client
                Array.Copy(this._serverWriteBuffer, 0, this._clientReadBuffer, 0, totalWritten);
                clientState = clientContext.ReadSsl
                (
                    new ReadOnlySpan<byte>(this._clientReadBuffer, 0, totalWritten),
                    this._clientWriteBuffer,
                    out totalRead,
                    out totalWritten
                );
            }

            //save session
            SslSession previousSession = clientContext.Session;
            //create new server context using old ssl context
            Ssl newServerContext = Ssl.CreateServerSsl
            (
                serverContext.SslContext
            );
            Assert.True(newServerContext.IsServer);

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();

            //create client
            Ssl newClientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol,
                previousSession: previousSession
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                newServerContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                newClientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            Assert.True(newClientContext.IsSessionReused);

            DoSynchronousShutdown
            (
                newServerContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                newClientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            newServerContext.Dispose();
            newClientContext.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestCretificateValidation(SslProtocol sslProtocol)
        {
            bool validationCalled = false;

            bool RemoteCertificateValidation(bool preVerifySucceeded, X509Certificate cert, IReadOnlyCollection<X509Certificate> certList)
            {
                Assert.Equal(cert, this._sslTestContext.ServerCertificate);
                validationCalled = true;
                return true;
            };

            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol,
                remoteCertificateValidationHandler: new RemoteCertificateValidationHandler(RemoteCertificateValidation)
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            Assert.True(validationCalled);

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestCAValidation(SslProtocol sslProtocol)
        {
            bool validationCalled = false;

            bool RemoteCertificateValidation(bool preVerifySucceeded, X509Certificate cert, IReadOnlyCollection<X509Certificate> certList)
            {
                Assert.Contains(this._sslTestContext.CACertificate, certList);
                Assert.True(preVerifySucceeded);
                validationCalled = true;
                return true;
            };

            //Create a store containing valid CA
            X509Store clientStore = new X509Store
            (
                new X509Certificate[]
                {
                    this._sslTestContext.CACertificate
                }
            );

            Assert.True(clientStore.Verify(this.ServerCertificate, out VerifyResult verifyResult));

            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol,
                certificateStore: clientStore,
                //not mandatory! used to assert tests
                remoteCertificateValidationHandler: new RemoteCertificateValidationHandler(RemoteCertificateValidation)
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            Assert.True(validationCalled);

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();

            clientStore.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestClientCertificateCallback(SslProtocol sslProtocol)
        {
            bool clientCallbackCalled = false;

            //used to select a client certificate
            bool ClientCertificateCallbackHandler
            (
                IReadOnlyCollection<X509Name> validCA,
                out X509Certificate clientCertificate,
                out PrivateKey clientPrivateKey
            )
            {
                Assert.NotEmpty(validCA);

                using (X509Name clientValidName = validCA.First())
                {
                    Assert.NotNull(clientValidName);
                    Assert.Equal("Root", clientValidName.Common);
                }

                clientCertificate = this._sslTestContext.ClientCertificate;
                clientPrivateKey = this._sslTestContext.ClientKey;

                return (clientCallbackCalled = true);
            }

            bool validationCalled = false;

            //used to validate the client certificate
            bool RemoteCertificateValidation(bool preVerifySucceeded, X509Certificate cert, IReadOnlyCollection<X509Certificate> certList)
            {
                Assert.Contains(this._sslTestContext.CACertificate, certList);
                Assert.True(preVerifySucceeded);
                validationCalled = true;
                return true;
            };

            //initialize server store
            X509Store serverStore = new X509Store
            (
                new X509Certificate[]
                {
                    this._sslTestContext.CACertificate
                }
            );

            Assert.True(serverStore.Verify(this.ClientCertificate, out VerifyResult verifyResult));

            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey,
                certificateStore: serverStore,
                //not mandatory! used to assert tests
                remoteCertificateValidationHandler: new RemoteCertificateValidationHandler(RemoteCertificateValidation)
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol,
                clientCertificateCallbackHandler: new ClientCertificateCallbackHandler(ClientCertificateCallbackHandler)
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            Assert.True(clientCallbackCalled);
            Assert.True(validationCalled);

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();

            serverStore.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestClientCertificate(SslProtocol sslProtocol)
        {
            bool validationCalled = false;

            //used to validate the client certificate
            bool RemoteCertificateValidation(bool preVerifySucceeded, X509Certificate cert, IReadOnlyCollection<X509Certificate> certList)
            {
                Assert.Contains(this._sslTestContext.CACertificate, certList);
                Assert.True(preVerifySucceeded);
                validationCalled = true;
                return true;
            };

            //initialize server store for client certificate validation
            X509Store serverStore = new X509Store
            (
                new X509Certificate[]
                {
                    this._sslTestContext.CACertificate
                }
            );

            Assert.True(serverStore.Verify(this.ClientCertificate, out VerifyResult verifyResult));

            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey,
                certificateStore: serverStore,
                //not mandatory! used to assert tests
                remoteCertificateValidationHandler: new RemoteCertificateValidationHandler(RemoteCertificateValidation)
            );
            Assert.True(serverContext.IsServer);

            //create client with client certificate
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ClientCertificate,
                privateKey: this.ClientKey
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            Assert.True(validationCalled);

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();

            serverStore.Dispose();
        }

        [Theory]
        [InlineData(SslProtocol.Tls12, "AES128-GCM-SHA256")]
        [InlineData(SslProtocol.Tls13, "TLS_CHACHA20_POLY1305_SHA256")]
        public void TsetCustomCipher(SslProtocol sslProtocol, string cipher)
        {
            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: sslProtocol,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol,
                ciphers: new string[] { cipher }
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Theory]
        [InlineData(128, 1024, 1024 * 1024)]
        [InlineData(1024, 128, 1024 * 1024)]
        [InlineData(1024 * 4, 1024 * 8, 1024 * 1024)]
        [InlineData(1024 * 8, 1024 * 4, 1024 * 1024)]
        [InlineData(1024 * 16 * 4, 1024 * 16 * 2, 1024 * 1024)]
        [InlineData(1024 * 16 * 2, 1024 * 16 * 4, 1024 * 1024)]
        public void TestRandomData(int sslBufferSize, int bufferSize, int testSize)
        {
            long read = 0;

            byte[] writeArr = new byte[bufferSize];
            byte[] readArr = new byte[bufferSize];

            Span<byte> writeSpan, readSpan, buf;
            int size;
            SslState clientState, serverState;
            int clientRead, serverRead, clientWritten, serverWritten;
            int totalRead, totalWritten;

            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: SslProtocol.Tls13,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: SslProtocol.Tls13
            );
            Assert.False(clientContext.IsServer);

            byte[] serverReadBuffer = ArrayPool<byte>.Shared.Rent(sslBufferSize);
            byte[] serverWriteBuffer = ArrayPool<byte>.Shared.Rent(sslBufferSize);
            byte[] clientReadBuffer = ArrayPool<byte>.Shared.Rent(sslBufferSize);
            byte[] clientWriteBuffer = ArrayPool<byte>.Shared.Rent(sslBufferSize);

            try
            {
                DoSynchronousHandshake
                (
                    serverContext,
                    serverWriteBuffer,
                    serverReadBuffer,
                    clientContext,
                    clientWriteBuffer,
                    clientReadBuffer
                );

                //send ±1GB of encrypted data from server to client
                while (read < testSize)
                {
                    size = RandomNumberGenerator.GetInt32(4, bufferSize);
                    Assert.NotEqual(0, size);

                    //fill buffer with random data
                    writeSpan = new Span<byte>(writeArr, 0, size);

                    //worth about 1/4 CPU time of test method (!!!)
                    Interop.Random.PseudoBytes(writeSpan);

                    totalRead = 0;
                    totalWritten = 0;

                    buf = writeSpan;

                    do
                    {
                        serverRead = serverWritten = 0;
                        clientRead = clientWritten = 0;

                        //encrypt (partial) data
                        serverState = serverContext.WriteSsl
                        (
                            buf,
                            serverWriteBuffer,
                            out serverRead,
                            out serverWritten
                        );

                        Assert.True(serverRead <= size);
                        totalRead += serverRead;
                        buf = writeSpan.Slice(totalRead);

                        if (serverWritten > 0)
                        {
                            Array.Copy(serverWriteBuffer, 0, clientReadBuffer, 0, serverWritten);
                        }

                        //write (partial) encrypted data to client
                        clientState = clientContext.ReadSsl
                        (
                            new ReadOnlySpan<byte>(clientReadBuffer, 0, serverWritten),
                            clientWriteBuffer,
                            out clientRead,
                            out clientWritten
                        );

                        if(clientWritten == 0)
                        {
                            continue;
                        }

                        //copy to result array
                        Array.Copy(clientWriteBuffer, 0, readArr, totalWritten, clientWritten);

                        //increment index
                        totalWritten += clientWritten;
                        
                    } while (totalRead != totalWritten);

                    Assert.Equal(size, totalWritten);
                    Assert.Equal(totalWritten, totalRead);

                    readSpan = new Span<byte>(readArr, 0, totalRead);

                    Assert.True
                    (
                        readSpan.SequenceEqual(writeSpan)
                    );

                    //increment read size
                    read += totalRead;
                }

                DoSynchronousShutdown
                (
                    serverContext,
                    serverWriteBuffer,
                    serverReadBuffer,
                    clientContext,
                    clientWriteBuffer,
                    clientReadBuffer
                );
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(serverReadBuffer);
                ArrayPool<byte>.Shared.Return(serverWriteBuffer);
                ArrayPool<byte>.Shared.Return(clientReadBuffer);
                ArrayPool<byte>.Shared.Return(clientWriteBuffer);
            }

            serverContext.Dispose();
            clientContext.Dispose();
        }
    }
}
