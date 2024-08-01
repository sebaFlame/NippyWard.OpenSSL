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

using NippyWard.OpenSSL.X509;
using NippyWard.OpenSSL.Keys;
using NippyWard.OpenSSL.SSL;
using NippyWard.OpenSSL.SSL.Buffer;

namespace NippyWard.OpenSSL.Tests
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
            bool clientRenegotiate,
            CancellationToken cancellationToken
        )
        {
            await client.Connect(target, cancellationToken);

            byte[] writeArr = new byte[bufferSize];
            long read = 0;
            int size;
            Memory<byte> writeMemory;
            int renegotiate = testSize / 2;

            bool doRenegotiate = (clientRenegotiate && !client.IsServer)
                || (!clientRenegotiate && client.IsServer);

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

            while (!doRenegotiate
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
                    && doRenegotiate)
                {
                    await client.Renegotiate
                    (
                        target,
                        cancellationToken
                    );

                    renegotiate = int.MaxValue;
                }
            }

            if (doRenegotiate)
            {
                await client.Disconnect(target, cancellationToken);
            }

            await readThread;
        }

        
        [Theory]
        [InlineData(1024, 1024 * 1024, SslProtocol.Tls12, false)]
        [InlineData(1024, 1024 * 1024, SslProtocol.Tls13, true)]
        [InlineData(1024, 1024 * 1024, SslProtocol.Tls13, false)]
        public async Task ThreadingTest
        (
            int bufferSize,
            int testSize,
            SslProtocol sslProtocol,
            bool clientRenegotiate
        )
        {
            SslCient server = new SslCient(this._testOutputHelper, sslProtocol, this.ServerCertificate, this.ServerKey);
            SslCient client = new SslCient(this._testOutputHelper, sslProtocol);

            try
            {
                await Task.WhenAll
                (
                    Client(server, client, bufferSize, testSize, clientRenegotiate, CancellationToken.None),
                    Client(client, server, bufferSize, testSize, clientRenegotiate, CancellationToken.None)
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
            private ITestOutputHelper _testOuptuHelper;

            private SemaphoreSlim _writeSemaphore;
            private TaskCompletionSource? _renegotiateTcs;

            //client
            public SslCient(ITestOutputHelper testOutput, SslProtocol sslProtocol)
            {
                this._testOuptuHelper = testOutput;

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
                ITestOutputHelper testOutput,
                SslProtocol sslProtocol,
                X509Certificate cert,
                PrivateKey key
            )
            {
                this._testOuptuHelper = testOutput;

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
                    if (sslState.WantsWrite())
                    {
                        await this.Write
                        (
                            target,
                            ReadOnlyMemory<byte>.Empty,
                            cancellationToken,
                            true
                        );
                    }
                    else if (sslState.WantsRead())
                    {
                        buf = await this.Read
                        (
                            target,
                            cancellationToken,
                            true
                        );

                        Assert.Empty(buf);
                    }
                }
            }

            public async Task<byte[]> Read
            (
                SslCient target,
                CancellationToken cancellationToken,
                bool duringHandshake = false
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

                    if (sslState.HandshakeCompleted())
                    {
                        this._testOuptuHelper.WriteLine($"HandshakeCompleted with {sslState} on {(this.IsServer ? "Server" : "Client")} during {(duringHandshake ? "handshake" : "renegotiation")} on Read");
                        this._renegotiateTcs?.SetResult();
                    }
                } while (sslState.WantsRead());

                if (sslState.WantsWrite())
                {
                    await this.Write
                    (
                        target,
                        ReadOnlyMemory<byte>.Empty,
                        cancellationToken
                    );
                }
                else if (sslState.IsShutdown())
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
                CancellationToken cancellationToken,
                bool duringHandshake = false
            )
            {
                PipeWriter pipeWriter = target._pipeWriter;
                SslState sslState;
                int read, index;
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

                        if (sslState.HandshakeCompleted())
                        {
                            this._testOuptuHelper.WriteLine($"HandshakeCompleted with {sslState} on {(this.IsServer ? "Server" : "Client")} during {(duringHandshake ? "handshake" : "renegotiation")} on Write");
                            this._renegotiateTcs?.SetResult();
                        }
                    } while (sslState.WantsWrite());
                }
                finally
                {
                    this._writeSemaphore.Release();
                }

                if (sslState.WantsRead())
                {
                    //buf = await this.Read
                    //(
                    //    target,
                    //    cancellationToken
                    //);

                    //Assert.Empty(buf);

                    //always reading
                }
                else
                {
                    Assert.Equal(buffer.Length, index);
                    Assert.Equal(SslState.NONE, sslState);
                }

                if (sslState.IsShutdown())
                {
                    //random not representative error (for testing)
                    throw new InvalidOperationException();
                }
            }

            //to simulate non-application data
            public async Task Renegotiate
            (
                SslCient target,
                CancellationToken cancellationToken
            )
            {
                SslState sslState;
                //create with TaskCreationOptions.RunContinuationsAsynchronously
                //else there is a deadlock (due to TESTing code)
                //even though this is also good practice in production!
                this._renegotiateTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

                try
                {
                    sslState = this._ssl.DoRenegotiate();

                    //could already be completed (TLS1.3)
                    if (sslState.HandshakeCompleted())
                    {
                        this._testOuptuHelper.WriteLine($"HandshakeCompleted with {sslState} on {(this.IsServer ? "Server" : "Client")} during Renegotiate");
                        this._renegotiateTcs.SetResult();
                    }

                    if (sslState.WantsWrite())
                    {
                        await this.Write
                        (
                            target,
                            ReadOnlyMemory<byte>.Empty,
                            cancellationToken
                        );
                    }

                    await this._renegotiateTcs.Task;
                }
                finally
                {
                    this._renegotiateTcs = null;
                }
            }

            public async Task Disconnect
            (
                SslCient target,
                CancellationToken cancellationToken
            )
            {
                this._ssl.DoShutdown(out SslState sslState);

                if (sslState.WantsWrite())
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
