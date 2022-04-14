using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using Xunit;
using Xunit.Abstractions;
using System.IO.Pipelines;

using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.SSL;
using OpenSSL.Core.SSL.Buffer;

namespace OpenSSL.Core.Tests
{
    public class TestSSLBufferThreading : IClassFixture<SslTestContext>
    {
        private X509Certificate ServerCertificate => this._sslTestContext.ServerCertificate;
        private PrivateKey ServerKey => this.ServerCertificate.PublicKey;

        private X509Certificate ClientCertificate => this._sslTestContext.ClientCertificate;
        private PrivateKey ClientKey => this.ClientCertificate.PublicKey;

        private ITestOutputHelper _testOutputHelper;
        private SslTestContext _sslTestContext;

        public TestSSLBufferThreading(ITestOutputHelper testOutputHelper, SslTestContext sslContext)
        {
            this._testOutputHelper = testOutputHelper;
            this._sslTestContext = sslContext;
        }

        private static async Task Client
        (
            SslCient client,
            SslCient target,
            int bufferSize,
            int testSize,
            CancellationToken cancellationToken
        )
        {
            await client.Connect(target, cancellationToken);

            byte[] writeArr = new byte[bufferSize];
            long read = 0;
            int size;
            Memory<byte> writeMemory;
            int renegotiate = testSize / 2;

            async Task ReadThread(CancellationToken cancellationToken)
            {
                byte[] res;
                while(true)
                {
                    try
                    {
                        res = await client.Read
                        (
                            target,
                            cancellationToken
                        );
                    }
                    //throws InvalidOperationException when PipeWriter completed
                    //throws InvalidOperationException when SslState.Shutdown
                    catch (InvalidOperationException)
                    {
                        break;
                    }
                }
            }

            Task readThread = ReadThread(cancellationToken);

            while (client.IsServer
                || read < testSize)
            {
                size = RandomNumberGenerator.GetInt32(4, bufferSize);
                writeMemory = new Memory<byte>(writeArr, 0, size);
                Interop.Random.PseudoBytes(writeMemory.Span);

                try
                {
                    await client.Write
                    (
                        target,
                        writeMemory,
                        cancellationToken
                    );
                }
                //throws InvalidOperationException when PipeWriter completed
                //throws InvalidOperationException when SslState.Shutdown
                catch (InvalidOperationException)
                {
                    break;
                }

                read += size;

                if (read > renegotiate
                    && !client.IsServer)
                {
                    await client.Renegotiate
                    (
                        target,
                        cancellationToken
                    );

                    renegotiate = int.MaxValue;
                }
            }

            if (!client.IsServer)
            {
#if DEBUG
                try
                {
                    //only check when not TLS1.3
                    if ((client._ssl.Protocol & SslProtocol.Tls13) == 0)
                    {
                        Assert.False(target._ssl.IsRenegotiatePending);
                        Assert.False(client._ssl.IsRenegotiatePending);

                        Assert.Equal(1, client._ssl.RenegotitationCount);
                    }
                }
                finally
                {
#endif
                    await client.Disconnect(target, cancellationToken);
#if DEBUG
                }
#endif
            }

            await readThread;
        }

        [Theory]
        [InlineData(1024, 1024 * 1024, SslProtocol.Tls12)]
        [InlineData(1024, 1024 * 1024, SslProtocol.Tls13)]
        public async Task ThreadingTest
        (
            int bufferSize,
            int testSize,
            SslProtocol sslProtocol
        )
        {
            SslCient server = new SslCient(sslProtocol, this.ServerCertificate, this.ServerKey);
            SslCient client = new SslCient(sslProtocol);

            try
            {
                await Task.WhenAll
                (
                    Client(server, client, bufferSize, testSize, CancellationToken.None),
                    Client(client, server, bufferSize, testSize, CancellationToken.None)
                );
            }
            finally
            {
                server.Dispose();
                client.Dispose();
            }
        }

        private class SslCient : IDisposable
        {
            public bool IsServer { get; }

            internal Ssl _ssl;
            private PipeReader _pipeReader;
            private PipeWriter _pipeWriter;
            private TlsBuffer _decryptedBuffer;

            private SemaphoreSlim _writeSemaphore;

            //client
            public SslCient(SslProtocol sslProtocol)
            {
                Pipe pipe = new Pipe();
                this._pipeReader = pipe.Reader;
                this._pipeWriter = pipe.Writer;

                this._decryptedBuffer = new TlsBuffer();

                this._ssl = Ssl.CreateClientSsl
                (
                    sslProtocol: sslProtocol
                );

                this.IsServer = this._ssl.IsServer;
                this._writeSemaphore = new SemaphoreSlim(1);
            }

            //server
            public SslCient
            (
                SslProtocol sslProtocol,
                X509Certificate cert,
                PrivateKey key
            )
            {
                //read pipe
                Pipe readPipe = new Pipe();
                this._pipeReader = readPipe.Reader;
                this._pipeWriter = readPipe.Writer;

                this._decryptedBuffer = new TlsBuffer();

                this._ssl = Ssl.CreateServerSsl
                (
                    sslProtocol: sslProtocol,
                    certificate: cert,
                    privateKey: key
                );

                this.IsServer = this._ssl.IsServer;
                this._writeSemaphore = new SemaphoreSlim(1);
            }

            public async Task Connect
            (
                SslCient target,
                CancellationToken cancellationToken
            )
            {
                SslState sslState;
                byte[] buf;

                while (!this._ssl.DoHandshake(out sslState))
                {
                    if (sslState == SslState.WANTWRITE)
                    {
                        await this.Write
                        (
                            target,
                            ReadOnlyMemory<byte>.Empty,
                            cancellationToken
                        );
                    }
                    else if (sslState == SslState.WANTREAD)
                    {
                        buf = await this.Read
                        (
                            target,
                            cancellationToken
                        );

                        Assert.Empty(buf);
                    }
                }
            }

            public async Task<byte[]> Read
            (
                SslCient target,
                CancellationToken cancellationToken
            )
            {
                PipeReader pipeReader = this._pipeReader;
                SslState sslState;
                SequencePosition read;
                ReadResult readResult;
                ReadOnlySequence<byte> buffer;

                do
                {
                    readResult = await pipeReader.ReadAsync(cancellationToken);

                    if(readResult.IsCompleted)
                    {
                        throw new InvalidOperationException();
                    }

                    buffer = readResult.Buffer;

                    sslState = this._ssl.ReadSsl
                    (
                        buffer,
                        this._decryptedBuffer,
                        out read
                    );

                    pipeReader.AdvanceTo(read, buffer.End);
                } while (sslState == SslState.WANTREAD);

                if (sslState == SslState.WANTWRITE)
                {
                    await this.Write
                    (
                        target,
                        ReadOnlyMemory<byte>.Empty,
                        cancellationToken
                    );
                }
                else if (sslState == SslState.SHUTDOWN)
                {
                    this._pipeWriter.Complete();
                    throw new InvalidOperationException();
                }

                this._decryptedBuffer.CreateReadOnlySequence(out ReadOnlySequence<byte> decrypted);
                byte[] result = decrypted.ToArray();
                this._decryptedBuffer.AdvanceReader(decrypted.End);

                return result;
            }

            public async Task Write
            (
                SslCient target,
                ReadOnlyMemory<byte> buffer,
                CancellationToken cancellationToken
            )
            {
                PipeWriter pipeWriter = target._pipeWriter;
                SslState sslState;
                int read, index;
                byte[] buf;
                ReadOnlyMemory<byte> writeBuf;
                index = 0;

                writeBuf = buffer;

                await this._writeSemaphore.WaitAsync();
                try
                {
                    do
                    {
                        sslState = this._ssl.WriteSsl
                        (
                            writeBuf.Span,
                            pipeWriter,
                            out read
                        );

                        index += read;
                        writeBuf = buffer.Slice(index);

                        //send data
                        await pipeWriter.FlushAsync(cancellationToken);
                    } while (sslState == SslState.WANTWRITE);
                }
                finally
                {
                    this._writeSemaphore.Release();
                }

                if (sslState == SslState.WANTREAD)
                {
                    //buf = await this.Read
                    //(
                    //    target,
                    //    cancellationToken
                    //);

                    //Assert.Empty(buf);

                    //always reading
                }
                else if (sslState == SslState.SHUTDOWN)
                {
                    throw new InvalidOperationException();
                }
                else
                {
                    Assert.Equal(buffer.Length, read);
                    Assert.Equal(SslState.NONE, sslState);
                }
            }

            //to simulate non-application data
            public async Task Renegotiate
            (
                SslCient target,
                CancellationToken cancellationToken
            )
            {
                SslState state = this._ssl.DoRenegotiate();

                if (state == SslState.WANTWRITE)
                {
                    await this.Write
                    (
                        target,
                        ReadOnlyMemory<byte>.Empty,
                        cancellationToken
                    );
                }
            }

            public async Task Disconnect
            (
                SslCient target,
                CancellationToken cancellationToken
            )
            {
                this._ssl.DoShutdown(out SslState sslState);

                if (sslState == SslState.WANTWRITE)
                {
                    await this.Write
                    (
                        target,
                        ReadOnlyMemory<byte>.Empty,
                        cancellationToken
                    );
                }

                this._pipeWriter.Complete();
            }

            public void Dispose()
            {
                this._ssl.Dispose();
            }
        }
    }
}
