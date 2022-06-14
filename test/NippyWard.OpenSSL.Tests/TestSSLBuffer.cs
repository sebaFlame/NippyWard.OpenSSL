using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Buffers;
using System.Security.Cryptography;

using Xunit;
using Xunit.Abstractions;

using NippyWard.OpenSSL.X509;
using NippyWard.OpenSSL.Keys;
using NippyWard.OpenSSL.SSL;
using NippyWard.OpenSSL.SSL.Buffer;

namespace NippyWard.OpenSSL.Tests
{
    public class TestSSLBuffer : TestBase
    {
        private SslTestContext _sslTestContext;
        private static byte[] _ClientMessage = Encoding.ASCII.GetBytes("This is a message from the client");
        private static byte[] _ServerMessage = Encoding.ASCII.GetBytes("This is a message from the server");

        private X509Certificate ServerCertificate => this._sslTestContext.ServerCertificate;
        private PrivateKey ServerKey => this.ServerCertificate.PublicKey;

        private TlsBuffer _serverReadBuffer;
        private TlsBuffer _serverWriteBuffer;
        private TlsBuffer _clientReadBuffer;
        private TlsBuffer _clientWriteBuffer;

        public TestSSLBuffer(ITestOutputHelper outputHelper)
            : base(outputHelper)
        {
            this._sslTestContext = new SslTestContext();

            this._serverReadBuffer = new TlsBuffer();
            this._serverWriteBuffer = new TlsBuffer();
            this._clientReadBuffer = new TlsBuffer();
            this._clientWriteBuffer = new TlsBuffer();
        }

        protected override void Dispose(bool isDisposing)
        {
            this._sslTestContext.Dispose();
        }

        private static void WriteReadCycle
        (
            Ssl writeClient,
            TlsBuffer writeClientWriteBuffer,
            ref SslState writeClientState,
            Ssl readClient,
            TlsBuffer readClientReadBuffer,
            ref SslState readClientState
        )
        {
            SequencePosition readClientRead;
            ReadOnlySequence<byte> writeBuffer;

            while (writeClientState.WantsWrite())
            {
                //get the client buffer (non application data) to write
                //nothing (no application data) to actually write, thus empty
                writeClientState = writeClient.WriteSsl
                (
                    ReadOnlySpan<byte>.Empty,
                    writeClientWriteBuffer,
                    out _
                );

                //create the sequence
                writeClientWriteBuffer.CreateReadOnlySequence(out writeBuffer);

                //TODO: verify nothing has been read into readClientBuffer
                readClientState = readClient.ReadSsl
                (
                    writeBuffer,
                    readClientReadBuffer,
                    out readClientRead
                );

                //verify write was complete
                Assert.Equal(writeBuffer.End, readClientRead);

                //advance reader
                writeClientWriteBuffer.AdvanceReader(readClientRead);
            }
        }

        private static void DoSynchronousHandshake
        (
            Ssl serverContext,
            TlsBuffer serverWriter,
            TlsBuffer serverReader,
            Ssl clientContext,
            TlsBuffer clientWriter,
            TlsBuffer clientReader
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
                        clientWriter,
                        ref clientState,
                        serverContext,
                        serverReader,
                        ref serverState
                    );
                }else if (serverState.WantsWrite())
                {
                    WriteReadCycle
                    (
                        serverContext,
                        serverWriter,
                        ref serverState,
                        clientContext,
                        clientReader,
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
            TlsBuffer serverWriter,
            TlsBuffer serverReader,
            Ssl clientContext,
            TlsBuffer clientWriter,
            TlsBuffer clientReader
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
                        clientWriter,
                        ref clientState,
                        serverContext,
                        serverReader,
                        ref serverState
                    );
                }

                if (serverState.IsShutdown())
                {
                    serverContext.DoShutdown(out serverState);
                }

                if (serverState.WantsWrite())
                {
                    WriteReadCycle
                    (
                        serverContext,
                        serverWriter,
                        ref serverState,
                        clientContext,
                        clientReader,
                        ref clientState
                    );
                }
            } while (!serverContext.DoShutdown(out serverState)
                | !clientContext.DoShutdown(out clientState));

            Assert.Equal(SslState.NONE, serverState);
            Assert.Equal(SslState.NONE, clientState);
        }

        private static void DoRenegotiate
        (
            Ssl client1,
            TlsBuffer client1Writer,
            TlsBuffer client1Reader,
            Ssl client2,
            TlsBuffer client2Writer,
            TlsBuffer client2Reader
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
                CheckHandshakeCompleted();

                if (client1State.WantsWrite())
                {
                    WriteReadCycle
                    (
                        client1,
                        client1Writer,
                        ref client1State,
                        client2,
                        client2Reader,
                        ref client2State
                    );
                }else if (client2State.WantsWrite())
                {
                    WriteReadCycle
                    (
                        client2,
                        client2Writer,
                        ref client2State,
                        client1,
                        client1Reader,
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

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Theory]
        [SslProtocolData(SslProtocol.Tls12)]
        [SslProtocolData(SslProtocol.Tls13)]
        public void TestShutdown(SslProtocol sslProtocol)
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
            int totalRead;
            SequencePosition clientRead, serverRead;
            ReadOnlySequence<byte> writeBuffer, readBuffer;

            //send data from server
            serverState = serverContext.WriteSsl
            (
                _ServerMessage,
                this._serverWriteBuffer,
                out totalRead
            );

            Assert.Equal(_ServerMessage.Length, totalRead);

            //verify no further action needs to be taken
            Assert.Equal(SslState.NONE, serverState);

            //Read data on client
            this._serverWriteBuffer.CreateReadOnlySequence(out writeBuffer);
            clientState = clientContext.ReadSsl
            (
                in writeBuffer,
                this._clientReadBuffer,
                out clientRead
            );

            //verify no further action needs to be taken
            Assert.Equal(SslState.NONE, clientState);

            //verify entire buffer has been read
            Assert.Equal(writeBuffer.End, clientRead);

            //get read buffer
            this._clientReadBuffer.CreateReadOnlySequence(out readBuffer);

            //verify read data
            Assert.True
            (
                readBuffer.ToArray()
                    .SequenceEqual(_ServerMessage)
            );

            //advance reader(s) after processing
            this._serverWriteBuffer.AdvanceReader(clientRead);
            this._clientReadBuffer.AdvanceReader(readBuffer.End);

            //send data from client
            clientState = clientContext.WriteSsl
            (
                _ClientMessage,
                this._clientWriteBuffer,
                out totalRead
            );

            //verify no further action needs to be taken
            Assert.Equal(SslState.NONE, clientState);

            //verify all data has been read
            Assert.Equal(_ClientMessage.Length, totalRead);

            //read data on server
            this._clientWriteBuffer.CreateReadOnlySequence(out writeBuffer);
            serverState = serverContext.ReadSsl
            (
                in writeBuffer,
                this._serverReadBuffer,
                out serverRead
            );

            //verify no further action needs to be taken
            Assert.Equal(SslState.NONE, serverState);

            //verify entire buffer has been read
            Assert.Equal(writeBuffer.End, serverRead);

            //get read buffer
            this._serverReadBuffer.CreateReadOnlySequence(out readBuffer);

            //verify read data
            Assert.True
            (
                readBuffer.ToArray()
                    .SequenceEqual(_ClientMessage)
            );

            //advance reader after processing
            this._clientWriteBuffer.AdvanceReader(serverRead);
            this._serverReadBuffer.AdvanceReader(readBuffer.End);

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

            DoRenegotiate
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

            DoRenegotiate
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
        [InlineData(1024, 1024 * 1024)]
        [InlineData(1024 * 8, 1024 * 1024)]
        [InlineData(1024 * 4, 1024 * 1024)]
        [InlineData(1024 * 16 * 2, 1024 * 1024)]
        [InlineData(1024 * 16 * 4, 1024 * 1024)]
        public void TestRandomData
        (
            int bufferSize,
            int testSize
        )
        {
            long read = 0;
            byte[] writeArr = new byte[bufferSize];
            byte[] readArr = new byte[bufferSize];
            Span<byte> writeSpan, readSpan;
            int size, bufSize;
            ReadOnlySequence<byte> writeBuffer, readBuffer, buf;
            SequencePosition totalRead;
            SslState clientState, serverState;

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

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                this._serverReadBuffer,
                clientContext,
                this._clientWriteBuffer,
                this._clientReadBuffer
            );

            //send ±1GB of encrypted data from server to client
            while (read < testSize)
            {
                //minimum 8K (minimum segment size is 4K)
                size = RandomNumberGenerator.GetInt32(0, bufferSize);

                //fill buffer with random data
                writeSpan = new Span<byte>(writeArr, 0, size);

                //worth about 1/4 CPU time of test method (!!!)
                Interop.Random.PseudoBytes(writeSpan);

                //create a sequence from the buffer
                writeBuffer = new ReadOnlySequence<byte>(writeArr, 0, size);

                //write sequence to client
                serverState = serverContext.WriteSsl(in writeBuffer, this._serverWriteBuffer, out totalRead);
                Assert.Equal(SslState.NONE, serverState);
                Assert.Equal(writeBuffer.End, totalRead);

                //get write sequence to write to client
                this._serverWriteBuffer.CreateReadOnlySequence(out writeBuffer);

                //write in 2 parts to test jitter
                bufSize = (int)(writeBuffer.Length / 2);

                //write first encrypted buffer to client
                buf = writeBuffer.Slice(0, bufSize);
                clientState = clientContext.ReadSsl(in buf, this._clientReadBuffer, out totalRead);
                Assert.Equal(buf.End, totalRead);

                if (bufSize > 0)
                {
                    //check if it has the correct state
                    //this should not always be the case as it could get sliced on the end of a frame
                    Assert.True(clientState.WantsRead());

                    //write second encrypted buffer to client
                    buf = writeBuffer.Slice(bufSize);
                    clientState = clientContext.ReadSsl(in buf, this._clientReadBuffer, out totalRead);
                    Assert.Equal(buf.End, totalRead);

                    Assert.Equal(SslState.NONE, clientState);
                }
                else
                {
                    Assert.Equal(SslState.EMPTYBUFFER, clientState);
                }

                //get read sequence
                this._clientReadBuffer.CreateReadOnlySequence(out readBuffer);

                //verify
                readBuffer.CopyTo(readArr);
                readSpan = new Span<byte>(readArr, 0, (int)readBuffer.Length);
                
                Assert.True
                (
                    readSpan.SequenceEqual(writeSpan)
                );

                //increment read size
                read += readBuffer.Length;

                //advance both readers
                this._serverWriteBuffer.AdvanceReader(writeBuffer.End);
                this._clientReadBuffer.AdvanceReader(readBuffer.End);
            }

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
    }
}
