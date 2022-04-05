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

        private void DoSynchronousHandshake
        (
            Ssl serverContext,
            Ssl clientContext
        )
        {
            SslState clientState, serverState;
            int clientRead, serverRead, clientWritten, serverWritten;

            //make sure you ALWAYS read both
            while (!clientContext.DoHandshake(out clientState)
                    | !serverContext.DoHandshake(out serverState))
            {
                if(clientState == SslState.WANTWRITE)
                {
                    //get the client buffer
                    clientContext.WritePending(this._clientWriteBuffer, out clientWritten);

                    //and write it to the server
                    Array.Copy(this._clientWriteBuffer, 0, this._serverReadBuffer, 0, clientWritten);
                    serverContext.ReadPending
                    (
                        new ReadOnlySpan<byte>(this._serverReadBuffer, 0, clientWritten),
                        out serverRead
                    );

                    //verify write was complete
                    Assert.Equal(clientWritten, serverRead);
                }

                if (serverState == SslState.WANTWRITE)
                {
                    //get the server buffer
                    serverContext.WritePending(this._serverWriteBuffer, out serverWritten);

                    //and write it to the client
                    Array.Copy(this._serverWriteBuffer, 0, this._clientReadBuffer, 0, serverWritten);
                    clientContext.ReadPending
                    (
                        new ReadOnlySpan<byte>(this._clientReadBuffer, 0, serverWritten),
                        out clientRead
                    );

                    //verify write was complete
                    Assert.Equal(serverWritten, clientRead);
                }
            }
        }

        private void DoSynchronousShutdown
        (
            Ssl clientContext,
            Ssl serverContext
        )
        {
            SslState clientState, serverState;
            int clientRead, serverRead, clientWritten, serverWritten;

            //make sure you ALWAYS read both
            while (!clientContext.DoShutdown(out clientState)
                    & !serverContext.DoShutdown(out serverState))
            {
                if (clientState == SslState.WANTWRITE)
                {
                    //get the client buffer
                    clientContext.WritePending(this._clientWriteBuffer, out clientWritten);

                    //and write it to the server
                    Array.Copy(this._clientWriteBuffer, 0, this._serverReadBuffer, 0, clientWritten);
                    serverContext.ReadPending
                    (
                        new ReadOnlySpan<byte>(this._serverReadBuffer, 0, clientWritten),
                        out serverRead
                    );

                    //verify write was complete
                    Assert.Equal(clientWritten, serverRead);
                }

                if (serverState == SslState.WANTWRITE)
                {
                    //get the server buffer
                    serverContext.WritePending(this._serverWriteBuffer, out serverWritten);

                    //and write it to the client
                    Array.Copy(this._serverWriteBuffer, 0, this._clientReadBuffer, 0, serverWritten);
                    clientContext.ReadPending
                    (
                        new ReadOnlySpan<byte>(this._clientReadBuffer, 0, serverWritten),
                        out clientRead
                    );

                    //verify write was complete
                    Assert.Equal(serverWritten, clientRead);
                }
            }
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

            //variables to store actions
            SslState serverState, clientState;
            int clientRead, serverRead, clientWritten, serverWritten;

            //initialize server handshake
            Assert.False(serverContext.DoHandshake(out serverState));
            Assert.Equal(SslState.WANTREAD, serverState);

            //initialize client handshake
            Assert.False(clientContext.DoHandshake(out clientState));
            Assert.Equal(SslState.WANTWRITE, clientState);

            //get the client buffer
            clientContext.WritePending(this._clientWriteBuffer, out clientWritten);

            //and write it to the server
            Array.Copy(this._clientWriteBuffer, 0, this._serverReadBuffer, 0, clientWritten);
            serverContext.ReadPending
            (
                new ReadOnlySpan<byte>(this._serverReadBuffer, 0, clientWritten),
                out serverRead
            );

            //verify write was complete
            Assert.Equal(clientWritten, serverRead);

            //continue server handshake
            Assert.False(serverContext.DoHandshake(out serverState));
            Assert.Equal(SslState.WANTWRITE, serverState);

            //continue client handshake
            Assert.False(clientContext.DoHandshake(out clientState));
            Assert.Equal(SslState.WANTREAD, clientState);

            //get the server buffer
            serverContext.WritePending(this._serverWriteBuffer, out serverWritten);

            //and write it to the client
            Array.Copy(this._serverWriteBuffer, 0, this._clientReadBuffer, 0, serverWritten);
            clientContext.ReadPending
            (
                new ReadOnlySpan<byte>(this._clientReadBuffer, 0, serverWritten),
                out clientRead
            );

            //verify write was complete
            Assert.Equal(serverWritten, clientRead);

            //continue server handshake
            Assert.False(serverContext.DoHandshake(out serverState));
            Assert.Equal(SslState.WANTREAD, serverState);

            //continue client handshake
            Assert.False(clientContext.DoHandshake(out clientState));
            Assert.Equal(SslState.WANTWRITE, clientState);

            //get the client buffer
            clientContext.WritePending(this._clientWriteBuffer, out clientWritten);

            //and write it to the server
            Array.Copy(this._clientWriteBuffer, 0, this._serverReadBuffer, 0, clientWritten);
            serverContext.ReadPending
            (
                new ReadOnlySpan<byte>(this._serverReadBuffer, 0, clientWritten),
                out serverRead
            );
            //verify write was complete
            Assert.Equal(clientWritten, serverRead);

            //continue the handshake
            Assert.False(serverContext.DoHandshake(out serverState));
            Assert.Equal(SslState.WANTWRITE, serverState);

            //TODO: last write not mandatory?
            if(sslProtocol != SslProtocol.Tls13)
            {
                Assert.False(clientContext.DoHandshake(out clientState));
                Assert.Equal(SslState.WANTREAD, clientState);
            }

            //get the server buffer
            serverContext.WritePending(this._serverWriteBuffer, out serverWritten);

            //and write it to the client
            Array.Copy(this._serverWriteBuffer, 0, this._clientReadBuffer, 0, serverWritten);
            clientContext.ReadPending
            (
                new ReadOnlySpan<byte>(this._clientReadBuffer, 0, serverWritten),
                out clientRead
            );

            //verify write was complete
            Assert.Equal(serverWritten, clientRead);

            //finish handshake
            Assert.True(serverContext.DoHandshake(out serverState));
            Assert.True(clientContext.DoHandshake(out clientState));

            Assert.Equal(SslState.NONE, serverState);
            Assert.Equal(SslState.NONE, clientState);

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

            this.DoSynchronousHandshake(serverContext, clientContext);

            //variables to store actions
            SslState serverState, clientState;
            int clientRead, serverRead, clientWritten, serverWritten;

            //continue server handshake
            Assert.False(serverContext.DoShutdown(out serverState));
            Assert.Equal(SslState.WANTWRITE, serverState);

            //continue client handshake
            Assert.False(clientContext.DoShutdown(out clientState));
            Assert.Equal(SslState.WANTWRITE, clientState);

            //get the server buffer
            serverContext.WritePending(this._serverWriteBuffer, out serverWritten);

            //and write it to the client
            Array.Copy(this._serverWriteBuffer, 0, this._clientReadBuffer, 0, serverWritten);
            clientContext.ReadPending
            (
                new ReadOnlySpan<byte>(this._clientReadBuffer, 0, serverWritten),
                out clientRead
            );

            //verify write was complete
            Assert.Equal(serverWritten, clientRead);

            //get the client buffer
            clientContext.WritePending(this._clientWriteBuffer, out clientWritten);

            //and write it to the server
            Array.Copy(this._clientWriteBuffer, 0, this._serverReadBuffer, 0, clientWritten);
            serverContext.ReadPending
            (
                new ReadOnlySpan<byte>(this._serverReadBuffer, 0, clientWritten),
                out serverRead
            );
            //verify write was complete
            Assert.Equal(clientWritten, serverRead);

            //finish shutdown
            Assert.True(serverContext.DoShutdown(out serverState));
            Assert.True(clientContext.DoShutdown(out clientState));

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestSslData(SslProtocol sslProtocol)
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

            this.DoSynchronousHandshake(serverContext, clientContext);

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

            this.DoSynchronousShutdown(serverContext, clientContext);

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

            this.DoSynchronousHandshake(serverContext, clientContext);

            this.Renegotiate(serverContext, clientContext);

            this.DoSynchronousShutdown(serverContext, clientContext);

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

            this.DoSynchronousHandshake(serverContext, clientContext);

            this.Renegotiate(clientContext, serverContext);

            this.DoSynchronousShutdown(serverContext, clientContext);

            serverContext.Dispose();
            clientContext.Dispose();
        }

        //the tests using this function are mostly used to test the
        //coherence between ReadSsl/WriteSsl and SslState.WANTREAD/SslState.WANTWRITE
        private void Renegotiate
        (
            Ssl client1,
            Ssl client2
        )
        {
            SslState client1State, client2State;
            int client2Read, client1Read, client2Written, client1Written;

            //force new handshake with a writable buffer
            client1.Renegotiate(this._serverWriteBuffer, out client1Written);

            //and write it to the client
            //do a regular (!) read on the client (this is after initial handshake)
            Array.Copy(this._serverWriteBuffer, 0, this._clientReadBuffer, 0, client1Written);
            client2State = client2.ReadSsl
            (
                new ReadOnlySpan<byte>(this._clientReadBuffer, 0, client1Written),
                this._clientWriteBuffer,
                out client2Read,
                out client2Written
            );

            //verify write was complete
            Assert.Equal(client1Written, client2Read);
            //and nothing got decrypted
            Assert.Equal(0, client2Written);

            //renegotiation finished
            if (client2State == SslState.NONE)
            {
                return;
            }

            //verify next action
            Assert.Equal(SslState.WANTWRITE, client2State);

            //get the renegotiation buffer form the client
            client2.WritePending
            (
                this._clientWriteBuffer,
                out client2Written
            );

            Assert.NotEqual(0, client2Written);

            //send the buffer back to the server
            Array.Copy(this._clientWriteBuffer, 0, this._serverReadBuffer, 0, client2Written);
            client1State = client1.ReadSsl
            (
                new ReadOnlySpan<byte>(this._serverReadBuffer, 0, client2Written),
                this._serverWriteBuffer,
                out client1Read,
                out client1Written
            );

            //verify write was complete
            Assert.Equal(client2Written, client1Read);
            //and nothing got decrypted
            Assert.Equal(0, client1Written);

            //renegotiation finished
            if (client1State == SslState.NONE)
            {
                return;
            }

            //verify next action
            Assert.Equal(SslState.WANTWRITE, client1State);

            //get the renegotiation buffer form the server
            client1.WritePending
            (
                this._serverWriteBuffer,
                out client1Written
            );

            Assert.NotEqual(0, client1Written);

            //send the buffer back to the client
            Array.Copy(this._serverWriteBuffer, 0, this._clientReadBuffer, 0, client1Written);
            client2State = client2.ReadSsl
            (
                new ReadOnlySpan<byte>(this._clientReadBuffer, 0, client1Written),
                this._clientWriteBuffer,
                out client2Read,
                out client2Written
            );

            //verify write was complete
            Assert.Equal(client1Written, client2Read);
            //and nothing got decrypted
            Assert.Equal(0, client2Written);

            //renegotiation finished
            if (client2State == SslState.NONE)
            {
                return;
            }

            //verify no further action is needed
            Assert.Equal(SslState.WANTWRITE, client2State);

            //get the renegotiation buffer form the client
            client2.WritePending
            (
                this._clientWriteBuffer,
                out client2Written
            );

            Assert.NotEqual(0, client2Written);

            //send the buffer back to the server
            Array.Copy(this._clientWriteBuffer, 0, this._serverReadBuffer, 0, client2Written);
            client1State = client1.ReadSsl
            (
                new ReadOnlySpan<byte>(this._serverReadBuffer, 0, client2Written),
                this._serverWriteBuffer,
                out client1Read,
                out client1Written
            );

            //verify next action
            Assert.Equal(SslState.NONE, client1State);

            //verify write was complete
            Assert.Equal(client2Written, client1Read);
            //and nothing got decrypted
            Assert.Equal(0, client1Written);
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

            this.DoSynchronousHandshake(serverContext, clientContext);

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

            this.DoSynchronousShutdown(serverContext, clientContext);

            serverContext.Dispose();
            clientContext.Dispose();

            //create client
            Ssl newClientContext = Ssl.CreateClientSsl
            (
                sslProtocol: sslProtocol,
                previousSession: previousSession
            );
            Assert.False(clientContext.IsServer);

            this.DoSynchronousHandshake(newServerContext, newClientContext);

            Assert.True(newClientContext.IsSessionReused);

            this.DoSynchronousShutdown(newServerContext, newClientContext);

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

            this.DoSynchronousHandshake(serverContext, clientContext);

            Assert.True(validationCalled);

            this.DoSynchronousShutdown(serverContext, clientContext);

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

            this.DoSynchronousHandshake(serverContext, clientContext);

            Assert.True(validationCalled);

            this.DoSynchronousShutdown(serverContext, clientContext);

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

            this.DoSynchronousHandshake(serverContext, clientContext);

            Assert.True(clientCallbackCalled);
            Assert.True(validationCalled);

            this.DoSynchronousShutdown(serverContext, clientContext);

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

            this.DoSynchronousHandshake(serverContext, clientContext);

            Assert.True(validationCalled);

            this.DoSynchronousShutdown(serverContext, clientContext);

            serverContext.Dispose();
            clientContext.Dispose();

            serverStore.Dispose();
        }
    }
}
