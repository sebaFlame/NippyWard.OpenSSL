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
using NippyWard.OpenSSL.Error;

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
            bool doRenegotiate,
            CancellationToken cancellationToken
        )
        {
            await client.Connect(target, cancellationToken);

            byte[] writeArr = new byte[bufferSize];
            long totalRead = 0;
            int size;
            Memory<byte> writeMemory;
            int renegotiate = testSize / 2;

            async Task ReadThread(CancellationToken cancellationToken)
            {
                while(true)
                {
                    SslState sslState;

                    try
                    {
                        sslState = await client.Read
                        (
                            target,
                            cancellationToken
                        );

                        if (sslState.IsShutdown())
                        {
                            if (client._ssl.DoShutdown(out sslState))
                            {
                                return;
                            }
                        }

                        if (sslState.WantsWrite())
                        {
                            (sslState, _) = await client.Write
                            (
                                target,
                                ReadOnlyMemory<byte>.Empty,
                                cancellationToken
                            );
                        }

                        if (sslState.IsShutdown())
                        {
                            if (client._ssl.DoShutdown(out sslState))
                            {
                                return;
                            }
                        }
                    }
                    catch(OpenSslException ex) when (ex.Errors.Any(x => x.Library == 20 && x.Reason == 207)) //protocol is shutdown
                    {
                        break;
                    }
                }
            }

            async Task WriteThread(CancellationToken cancellationToken)
            {
                while (totalRead < testSize
                    || !client.IsServer)
                {
                    size = RandomNumberGenerator.GetInt32(4, bufferSize);
                    writeMemory = new Memory<byte>(writeArr, 0, size);
                    Interop.Random.PseudoBytes(writeMemory.Span);
                    SslState sslState;
                    int read = 0, index = 0;
                    ReadOnlyMemory<byte> writeBuf;

                    try
                    {
                        do
                        {

                            writeBuf = writeMemory.Slice(index);

                            (sslState, read) = await client.Write
                            (
                                target,
                                writeBuf,
                                cancellationToken
                            );

                            index += read;

                            while (sslState.IsShutdown())
                            {
                                if (client._ssl.DoShutdown(out sslState))
                                {
                                    return;
                                }

                                if(sslState.WantsWrite())
                                {
                                    (sslState, read) = await client.Write
                                    (
                                        target,
                                        ReadOnlyMemory<byte>.Empty,
                                        cancellationToken
                                    );
                                }
                            }
                        } while (index < size);
                    }
                    catch (OpenSslException ex) when (ex.Errors.Any(x => x.Library == 20 && x.Reason == 207)) //protocol is shutdown
                    {
                        break;
                    }
                    //catch (Exception ex)
                    //{
                    //    break;
                    //}

                    totalRead += size;

                    if (totalRead > renegotiate
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
            }

            Task readThread = ReadThread(cancellationToken);
            Task writeThread = WriteThread(cancellationToken);

            await writeThread;

            if (client.IsServer)
            {
                await client.Disconnect(target, cancellationToken);
            }

            await readThread;
        }

        
        [Theory]
        [InlineData(1024, 1024 * 1024, SslProtocol.Tls12, true)]
        [InlineData(1024, 1024 * 1024, SslProtocol.Tls13, false)]
        public async Task ThreadingTest
        (
            int bufferSize,
            int testSize,
            SslProtocol sslProtocol,
            bool renegotiate
        )
        {
            SslCient server = new SslCient(this._testOutputHelper, sslProtocol, this.ServerCertificate, this.ServerKey);
            SslCient client = new SslCient(this._testOutputHelper, sslProtocol);

            try
            {
                await Task.WhenAll
                (
                    Client(server, client, bufferSize, testSize, renegotiate & server.IsServer, CancellationToken.None),
                    Client(client, server, bufferSize, testSize, renegotiate & client.IsServer, CancellationToken.None)
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
            internal TlsBuffer _decryptedBuffer;
            private ITestOutputHelper _testOuptuHelper;

            private SemaphoreSlim _writeSemaphore;
            private SemaphoreSlim _readSemaphore;
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
                this._readSemaphore = new SemaphoreSlim(1);
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
                this._readSemaphore = new SemaphoreSlim(1);
            }

            public async Task Connect
            (
                SslCient target,
                CancellationToken cancellationToken
            )
            {
                SslState sslState;

                while (!this._ssl.DoHandshake(out sslState))
                {
                    if (sslState.WantsWrite())
                    {
                        (sslState, _) = await this.Write
                        (
                            target,
                            ReadOnlyMemory<byte>.Empty,
                            cancellationToken
                        );
                    }
                    
                    if (sslState.WantsRead())
                    {
                        sslState = await this.Read
                        (
                            target,
                            cancellationToken
                        );
                    }
                }
            }

            public async Task<SslState> Read
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

                await this._readSemaphore.WaitAsync();
                try
                {
                    readResult = await pipeReader.ReadAsync(cancellationToken);

                    if (readResult.IsCompleted)
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

                    Assert.Equal(buffer.End, read);

                    this._decryptedBuffer.CreateReadOnlySequence(out ReadOnlySequence<byte> decrypted);
                    this._decryptedBuffer.AdvanceReader(decrypted.End);
                }
                finally
                {
                    this._readSemaphore.Release();
                }

                return sslState;
            }

            public async Task<(SslState, int)> Write
            (
                SslCient target,
                ReadOnlyMemory<byte> buffer,
                CancellationToken cancellationToken
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
                }
                finally
                {
                    this._writeSemaphore.Release();
                }

                return (sslState, index);
            }

            //to simulate non-application data
            public async Task Renegotiate
            (
                SslCient target,
                CancellationToken cancellationToken
            )
            {
                if(this._ssl.Protocol == SslProtocol.Tls13)
                {
                    return;
                }

                this._ssl.DoRenegotiate(out SslState sslState);

                if (sslState.WantsWrite())
                {
                    (sslState, _) = await this.Write
                    (
                        target,
                        ReadOnlyMemory<byte>.Empty,
                        CancellationToken.None
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

                if (sslState.WantsWrite())
                {
                    (sslState, _) = await this.Write
                    (
                        target,
                        ReadOnlyMemory<byte>.Empty,
                        CancellationToken.None
                    );
                }
            }

            public void Dispose()
            {
                //shutdown underlying transport
                this._pipeWriter.Complete();

                this._ssl.Dispose();
            }
        }
    }
}
