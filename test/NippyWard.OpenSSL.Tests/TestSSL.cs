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
using System.Diagnostics;

using Xunit;
using Xunit.Abstractions;

using NippyWard.OpenSSL.X509;
using NippyWard.OpenSSL.Keys;
using NippyWard.OpenSSL.SSL;

namespace NippyWard.OpenSSL.Tests
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

        private static void WriteReadCycle
        (
            Ssl writeClient,
            byte[] writeClientWriteBuffer,
            byte[] writeClientReadBuffer,
            ref SslState writeClientState,
            Ssl readClient,
            byte[] readClientWriteBuffer,
            byte[] readClientReadBuffer,
            ref SslState readClientState
        )
        {
            int writeClientWritten, writeClientRead, readClientRead,
                readClientWritten, readClientIndex, length;
            ReadOnlySpan<byte> readBuffer;

            while (writeClientState.WantsWrite())
            {
                //no actual data to write
                readBuffer = ReadOnlySpan<byte>.Empty;

                //get the client buffer
                writeClientState = writeClient.WriteSsl
                (
                    readBuffer,
                    writeClientWriteBuffer,
                    out writeClientRead,
                    out writeClientWritten
                );

                //check if nothing got encrypted
                Assert.Equal(0, writeClientRead);

                //reset indexing
                readClientIndex = 0;
                readClientRead = 0;
                readClientWritten = 0;

                //and write it to the server
                do
                {
                    length = writeClientWritten - readClientIndex;

                    if (length > readClientReadBuffer.Length)
                    {
                        length = readClientReadBuffer.Length;
                    }

                    Array.Copy
                    (
                        writeClientWriteBuffer,
                        readClientIndex,
                        readClientReadBuffer,
                        0,
                        length
                    );

                    readBuffer = new ReadOnlySpan<byte>
                    (
                        readClientReadBuffer,
                        0,
                        length
                    );

                    readClientState = readClient.ReadSsl
                    (
                        readBuffer,
                        readClientWriteBuffer,
                        out readClientRead,
                        out readClientWritten
                    );

                    //check if nothing got decrypted
                    Assert.Equal(0, readClientWritten);

                    readClientIndex += readClientRead;
                } while (readClientIndex < writeClientWritten);

                //verify write was complete
                Assert.Equal(writeClientWritten, readClientIndex);
            }
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
            bool clientComplete = false, serverComplete = false;

            Assert.False(serverContext.DoHandshake(out serverState));
            Assert.False(clientContext.DoHandshake(out clientState));
            Assert.True(clientState.WantsWrite());

            void CheckHandshakeCompleted()
            {
                if (clientState.HandshakeCompleted())
                {
                    //should be true even though a write is still needed
                    Assert.True(clientContext.DoHandshake(out _));

                    clientComplete = true;
                }

                if (serverState.HandshakeCompleted())
                {
                    //should be true even though a write is still needed
                    Assert.True(serverContext.DoHandshake(out _));

                    serverComplete = true;
                }
            }

            do
            {
                CheckHandshakeCompleted();

                if (clientState.WantsWrite())
                {
                    WriteReadCycle
                    (
                        clientContext,
                        clientWriteBuffer,
                        clientReadBuffer,
                        ref clientState,
                        serverContext,
                        serverWriteBuffer,
                        serverReadBuffer,
                        ref serverState
                    );
                }
                else if (serverState.WantsWrite())
                {
                    WriteReadCycle
                    (
                        serverContext,
                        serverWriteBuffer,
                        serverReadBuffer,
                        ref serverState,
                        clientContext,
                        clientWriteBuffer,
                        clientReadBuffer,
                        ref clientState
                    );
                }

                CheckHandshakeCompleted();
            } while (clientState.WantsWrite()
                || serverState.WantsWrite());

            Assert.True(clientComplete);
            Assert.True(serverComplete);

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
            SslState clientState = SslState.NONE, serverState = SslState.NONE;

            //usually initiated from 1 side
            clientContext.DoShutdown(out clientState);

            //make sure you ALWAYS read both
            do
            {
                if (clientState.WantsWrite())
                {
                    WriteReadCycle
                    (
                        clientContext,
                        clientWriteBuffer,
                        clientReadBuffer,
                        ref clientState,
                        serverContext,
                        serverWriteBuffer,
                        serverReadBuffer,
                        ref serverState
                    );
                }

                if(serverState.IsShutdown())
                {
                    serverContext.DoShutdown(out serverState);
                }

                if (serverState.WantsWrite())
                {
                    WriteReadCycle
                    (
                        serverContext,
                        serverWriteBuffer,
                        serverReadBuffer,
                        ref serverState,
                        clientContext,
                        clientWriteBuffer,
                        clientReadBuffer,
                        ref clientState
                    );
                }
            } while (!serverContext.DoShutdown(out serverState)
                | !clientContext.DoShutdown(out clientState));

            Assert.Equal(SslState.NONE, serverState);
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
            bool renegotiateCompleted = false;

            //force new handshake with a writable buffer
            client1State = client1.DoRenegotiate();

            Assert.True(client1State.WantsWrite());

            //only check the initiator
            void CheckHandshakeCompleted()
            {
                renegotiateCompleted |= client1State.HandshakeCompleted();
            }

            do
            {
                //renegotiate it can be completed before the write
                CheckHandshakeCompleted();

                if (client1State.WantsWrite())
                {
                    WriteReadCycle
                    (
                        client1,
                        client1WriteBuffer,
                        client1ReadBuffer,
                        ref client1State,
                        client2,
                        client2WriteBuffer,
                        client2ReadBuffer,
                        ref client2State
                    );
                }
                else if (client2State.WantsWrite())
                {
                    WriteReadCycle
                    (
                        client2,
                        client2WriteBuffer,
                        client2ReadBuffer,
                        ref client2State,
                        client1,
                        client1WriteBuffer,
                        client1ReadBuffer,
                        ref client1State
                    );
                }

                //renegotiate can be complete after the read
                CheckHandshakeCompleted();
            } while (client1State.WantsWrite()
                || client2State.WantsWrite());

            Assert.True(renegotiateCompleted);
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

            Debug.WriteLine("RENEGOTIATE");

            DoSynchrounousRenegotiate
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            Debug.WriteLine("SHUTDOWN");

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
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer,
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer
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
            using SslSession? previousSession = clientContext.Session;

            Assert.NotNull(previousSession);

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
        [InlineData(128, 256, 1024, 1024 * 1024)]
        [InlineData(256, 128, 1024, 1024 * 1024)]
        [InlineData(1024 * 4, 1024 * 8, 1024 * 8, 1024 * 1024)]
        [InlineData(1024 * 8, 1024 * 4, 1024 * 4, 1024 * 1024)]
        [InlineData(1024 * 16 * 4, 1024 * 16 * 2, 1024 * 16 * 2, 1024 * 1024)]
        [InlineData(1024 * 16 * 2, 1024 * 16 * 4, 1024 * 16 * 4, 1024 * 1024)]
        public void TestRandomData
        (
            int sslWriteBufferSize,
            int sslReadBufferSize,
            int bufferSize,
            int testSize
        )
        {
            long totalDecrypted = 0;

            byte[] writeArr = new byte[bufferSize];
            byte[] readArr = new byte[bufferSize];

            Span<byte> writeSpan, readSpan, buf;
            int size;
            SslState clientState = SslState.NONE, serverState = SslState.NONE;
            int clientRead, serverRead, clientWritten, serverWritten;
            int totalRead, totalWritten;
            ReadOnlySpan<byte> readBuf;
            int length, readClientIndex;

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

            byte[] serverReadBuffer = ArrayPool<byte>.Shared.Rent(sslReadBufferSize);
            byte[] serverWriteBuffer = ArrayPool<byte>.Shared.Rent(sslWriteBufferSize);
            byte[] clientReadBuffer = ArrayPool<byte>.Shared.Rent(sslReadBufferSize);
            byte[] clientWriteBuffer = ArrayPool<byte>.Shared.Rent(sslWriteBufferSize);

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
                while (totalDecrypted < testSize)
                {
                    //ensure it can handle zero byte writes
                    size = RandomNumberGenerator.GetInt32(0, bufferSize);

                    //fill buffer with random data
                    writeSpan = new Span<byte>(writeArr, 0, size);

                    //worth about 1/4 CPU time of test method (!!!)
                    Interop.Random.PseudoBytes(writeSpan);

                    totalRead = 0;
                    totalWritten = 0;
                    serverRead = serverWritten = 0;
                    clientRead = clientWritten = 0;

                    buf = writeSpan;

                    do
                    {
                        //encrypt (partial) data
                        serverState = serverContext.WriteSsl
                        (
                            buf,
                            serverWriteBuffer,
                            out serverRead,
                            out serverWritten
                        );

                        totalRead += serverRead;
                        buf = writeSpan.Slice(totalRead);

                        readClientIndex = 0;
                        clientRead = 0;

                        do
                        {
                            length = serverWritten - readClientIndex;

                            if (length > clientReadBuffer.Length)
                            {
                                length = clientReadBuffer.Length;
                            }

                            Array.Copy
                            (
                                serverWriteBuffer,
                                readClientIndex,
                                clientReadBuffer,
                                0,
                                length
                            );

                            readBuf = new ReadOnlySpan<byte>
                            (
                                clientReadBuffer,
                                0,
                                length
                            );

                            //write (partial) encrypted data to client
                            clientState = clientContext.ReadSsl
                            (
                                readBuf,
                                clientWriteBuffer,
                                out clientRead,
                                out clientWritten
                            );

                            readClientIndex += clientRead;

                            //ensure everything gets read before writing into clientWriteBuffer
                            if (clientWritten == 0
                                && readClientIndex == serverWritten)
                            {
                                break;
                            }

                            //copy to result array
                            Array.Copy(clientWriteBuffer, 0, readArr, totalWritten, clientWritten);

                            //increment index
                            totalWritten += clientWritten;

                        } while (clientState.WantsRead());
                    } while (serverState.WantsWrite());

                    Assert.Equal(totalRead, totalWritten);

                    readSpan = new Span<byte>(readArr, 0, totalRead);

                    Assert.True
                    (
                        readSpan.SequenceEqual(writeSpan)
                    );

                    //increment read size
                    totalDecrypted += totalRead;
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
