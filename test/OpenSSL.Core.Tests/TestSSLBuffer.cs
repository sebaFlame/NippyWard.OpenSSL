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
using OpenSSL.Core.Tests.Buffer;

namespace OpenSSL.Core.Tests
{
    public class TestSSLBuffer : TestBase
    {
        private SslTestContext _sslTestContext;
        private static byte[] _ClientMessage = Encoding.ASCII.GetBytes("This is a message from the client");
        private static byte[] _ServerMessage = Encoding.ASCII.GetBytes("This is a message from the server");

        private X509Certificate ServerCertificate => this._sslTestContext.ServerCertificate;
        private PrivateKey ServerKey => this.ServerCertificate.PublicKey;

        private X509Certificate ClientCertificate => this._sslTestContext.ClientCertificate;
        private PrivateKey ClientKey => this.ClientCertificate.PublicKey;

        private X509Certificate CACertificate => this._sslTestContext.CACertificate;

        private const int _DefaultBufferSize = 16383;

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

        private static void DoSynchronousHandshake
        (
            Ssl serverContext,
            TlsBuffer serverWriter,
            Ssl clientContext,
            TlsBuffer clientWriter
        )
        {
            SslState clientState, serverState;
            SequencePosition clientRead, serverRead;
            ReadOnlySequence<byte> writeBuffer;

            //make sure you ALWAYS read both
            while (!clientContext.DoHandshake(out clientState)
                    | !serverContext.DoHandshake(out serverState))
            {
                if (clientState == SslState.WANTWRITE)
                {
                    //get the client buffer
                    Assert.True(clientContext.WritePending(clientWriter));

                    //and write it to the server
                    clientWriter.CreateReadOnlySequence(out writeBuffer);
                    serverContext.ReadPending
                    (
                        writeBuffer,
                        out serverRead
                    );

                    //verify write was complete
                    Assert.Equal(writeBuffer.End, serverRead);

                    //advance internal buffer
                    clientWriter.AdvanceReader(serverRead);
                }

                if (serverState == SslState.WANTWRITE)
                {
                    //get the server buffer
                    Assert.True(serverContext.WritePending(serverWriter));

                    //and write it to the client
                    serverWriter.CreateReadOnlySequence(out writeBuffer);
                    clientContext.ReadPending
                    (
                        writeBuffer,
                        out clientRead
                    );

                    //verify write was complete
                    Assert.Equal(writeBuffer.End, clientRead);

                    //advance internal buffer
                    serverWriter.AdvanceReader(clientRead);
                }
            }
        }

        private static void DoSynchronousShutdown
        (
            Ssl serverContext,
            TlsBuffer serverWriter,
            Ssl clientContext,
            TlsBuffer clientWriter
        )
        {
            SslState clientState, serverState;
            SequencePosition clientRead, serverRead;
            ReadOnlySequence<byte> writeBuffer;

            //make sure you ALWAYS read both
            while (!clientContext.DoShutdown(out clientState)
                    & !serverContext.DoShutdown(out serverState))
            {
                if (clientState == SslState.WANTWRITE)
                {
                    //get the client buffer
                    Assert.True(clientContext.WritePending(clientWriter));

                    //and write it to the server
                    clientWriter.CreateReadOnlySequence(out writeBuffer);
                    serverContext.ReadPending
                    (
                        writeBuffer,
                        out serverRead
                    );

                    //verify write was complete
                    Assert.Equal(writeBuffer.End, serverRead);

                    //advance internal buffer
                    clientWriter.AdvanceReader(serverRead);
                }

                if (serverState == SslState.WANTWRITE)
                {
                    //get the server buffer
                    serverContext.WritePending(serverWriter);

                    //and write it to the client
                    serverWriter.CreateReadOnlySequence(out writeBuffer);
                    clientContext.ReadPending
                    (
                        writeBuffer,
                        out clientRead
                    );

                    //verify write was complete
                    Assert.Equal(writeBuffer.End, clientRead);

                    //advance internal buffer
                    serverWriter.AdvanceReader(clientRead);
                }
            }
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
            SequencePosition client1Read, client2Read;
            ReadOnlySequence<byte> writeBuffer, readBuffer;

            //force new handshake with a writable buffer
            client1.Renegotiate(client1Writer);

            //and write it to the client
            //do a regular (!) read on the client (this is after initial handshake)
            client1Writer.CreateReadOnlySequence(out writeBuffer);
            client2State = client2.ReadSsl
            (
                writeBuffer,
                client2Reader,
                out client2Read
            );

            //verify write was complete
            Assert.Equal(writeBuffer.End, client2Read);

            //and nothing got decrypted
            client2Reader.CreateReadOnlySequence(out readBuffer);
            Assert.Equal(0, readBuffer.Length);

            //advance both readers
            client1Writer.AdvanceReader(client2Read);
            client2Reader.AdvanceReader(readBuffer.End);

            while(client1State != SslState.NONE
                || client2State != SslState.NONE)
            {
                if(client1State == SslState.WANTWRITE)
                {
                    //get the renegotiation buffer form the client
                    Assert.True
                    (
                        client1.WritePending
                        (
                            client1Writer
                        )
                    );

                    //reset state
                    client1State = SslState.NONE;

                    //and read it into to the next client
                    client1Writer.CreateReadOnlySequence(out writeBuffer);
                    client2State = client2.ReadSsl
                    (
                        writeBuffer,
                        client2Reader,
                        out client2Read
                    );

                    //and nothing got decrypted
                    client2Reader.CreateReadOnlySequence(out readBuffer);
                    Assert.Equal(0, readBuffer.Length);

                    //advance both readers
                    client1Writer.AdvanceReader(client2Read);
                    client2Reader.AdvanceReader(readBuffer.End);
                }

                if(client2State == SslState.WANTWRITE)
                {
                    //get the renegotiation buffer form the client
                    Assert.True
                    (
                        client2.WritePending
                        (
                            client2Writer
                        )
                    );

                    //reset state
                    client2State = SslState.NONE;

                    //and read it into to the next client
                    client2Writer.CreateReadOnlySequence(out writeBuffer);
                    client1State = client1.ReadSsl
                    (
                        writeBuffer,
                        client1Reader,
                        out client1Read
                    );

                    //and nothing got decrypted
                    client1Reader.CreateReadOnlySequence(out readBuffer);
                    Assert.Equal(0, readBuffer.Length);

                    //advance both readers
                    client2Writer.AdvanceReader(client1Read);
                    client1Reader.AdvanceReader(readBuffer.End);
                }
            }

#if DEBUG
            //only check these when using TLS1.2
            Assert.False(client1.IsRenegotiatePending);
            Assert.False(client2.IsRenegotiatePending);
#endif
        }

        [Fact]
        public void TestHandshake()
        {
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
                clientContext,
                this._clientWriteBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Fact]
        public void TestShutdown()
        {
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
                clientContext,
                this._clientWriteBuffer
            );

            DoSynchronousShutdown
            (
                serverContext,
                this._serverWriteBuffer,
                clientContext,
                this._clientWriteBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Fact]
        public void TestSslData()
        {
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
                clientContext,
                this._clientWriteBuffer
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
                clientContext,
                this._clientWriteBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Fact]
        public void TestServerRenegotiate()
        {
            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: SslProtocol.Tls12,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: SslProtocol.Tls12
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                clientContext,
                this._clientWriteBuffer
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
                clientContext,
                this._clientWriteBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Fact]
        public void TestClientRenegotiate()
        {
            //create server
            Ssl serverContext = Ssl.CreateServerSsl
            (
                sslProtocol: SslProtocol.Tls12,
                certificate: this.ServerCertificate,
                privateKey: this.ServerKey
            );
            Assert.True(serverContext.IsServer);

            //create client
            Ssl clientContext = Ssl.CreateClientSsl
            (
                sslProtocol: SslProtocol.Tls12
            );
            Assert.False(clientContext.IsServer);

            DoSynchronousHandshake
            (
                serverContext,
                this._serverWriteBuffer,
                clientContext,
                this._clientWriteBuffer
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
                clientContext,
                this._clientWriteBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }

        [Fact]
        public void TestBigData()
        {
            int bufferSize = 1024 * 1024 * 4;
            long read = 0;
            byte[] arr = new byte[bufferSize];
            Span<byte> buffer;
            int size;
            ReadOnlySequence<byte> writeBuffer, readBuffer;
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
                clientContext,
                this._clientWriteBuffer
            );

            //send ±1GB of encrypted data from server to client
            while (read < 1024 * 1024 * 1024)
            {
                //minimum 8K (minimum segment size is 4K)
                size = RandomNumberGenerator.GetInt32(4096 * 2, bufferSize);

                //fill buffer with random data
                buffer = new Span<byte>(arr, 0, size);
                Interop.Random.PseudoBytes(buffer);

                //create a sequence from the buffer
                writeBuffer = new ReadOnlySequence<byte>(arr, 0, size);

                //write sequence to client
                serverState = serverContext.WriteSsl(in writeBuffer, this._serverWriteBuffer, out totalRead);
                Assert.Equal(SslState.NONE, serverState);
                Assert.Equal(writeBuffer.End, totalRead);

                //get write sequence to write to client
                this._serverWriteBuffer.CreateReadOnlySequence(out writeBuffer);

                //write encrypted buffer to client
                clientState = clientContext.ReadSsl(in writeBuffer, this._clientReadBuffer, out totalRead);
                Assert.Equal(SslState.NONE, clientState);
                Assert.Equal(writeBuffer.End, totalRead);

                //get read sequence
                this._clientReadBuffer.CreateReadOnlySequence(out readBuffer);

                //verify
                Assert.True
                (
                    new Span<byte>(readBuffer.ToArray())
                        .SequenceEqual(buffer)
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
                clientContext,
                this._clientWriteBuffer
            );

            serverContext.Dispose();
            clientContext.Dispose();
        }
    }
}
