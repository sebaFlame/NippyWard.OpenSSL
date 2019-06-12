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
using System.Collections.Concurrent;
using System.Text;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;

using Xunit;
using Xunit.Abstractions;

using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.ASN1;
using OpenSSL.Core.SSL;
using OpenSSL.Core.Collections;
using OpenSSL.Core.SSL.Pipelines;

namespace OpenSSL.Core.Tests
{
    public class TestSSL : TestBase
    {
        private SslTestContext ctx;
        static byte[] clientMessage = Encoding.ASCII.GetBytes("This is a message from the client");
        static byte[] serverMessage = Encoding.ASCII.GetBytes("This is a message from the server");

        private SocketServerImplementation serverListener;

        public TestSSL(ITestOutputHelper outputHelper)
            : base(outputHelper)
        {
            this.ctx = new SslTestContext();

            //create server
            this.serverListener = CreateServer();
        }

        protected override void Dispose(bool disposing)
        {
            this.serverListener?.Dispose();
            this.ctx?.Dispose();
        }

        private static SocketServerImplementation CreateServer()
        {
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Loopback, 0);
            SocketServerImplementation serverListener = new SocketServerImplementation();
            serverListener.Listen(serverEndPoint);

            return serverListener;
        }

        private static Task<SocketConnection> CreateClient(SocketServerImplementation serverListener)
        {
            IPEndPoint clientEndPoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)serverListener.Listener.LocalEndPoint).Port);
            return SocketConnection.ConnectAsync(clientEndPoint, name: "client");
        }

        private static async Task VerifyRead(SocketConnection client, SocketConnection server, byte[] message)
        {
            ReadResult readResult;

            ValueTask<FlushResult> flushResult = client.Output.WriteAsync(message);
            if (!flushResult.IsCompleted)
                await flushResult.ConfigureAwait(false);

            ValueTask<ReadResult> clientResult = server.Input.ReadAsync();
            if (!clientResult.IsCompleted)
                readResult = await clientResult.ConfigureAwait(false);
            else
                readResult = clientResult.Result;

            Assert.True(readResult.Buffer.IsSingleSegment);
            Assert.True(readResult.Buffer.First.Span.SequenceEqual(message));
            server.Input.AdvanceTo(readResult.Buffer.End);
        }

        private static Task DisposeConnections(SocketConnection client, ClientWrapper server)
        {
            return Task.WhenAll(Task.Factory.StartNew(client.Dispose), Task.Factory.StartNew(server.Dispose));
        }

        private static void VerifyEncryptionEnabled(SocketConnection client, X509Certificate remoteCertificate = null)
        {
            Assert.NotEmpty(client.Cipher);
            Assert.True(client.Protocol >= SslProtocol.Tls12);
            if (!(remoteCertificate is null))
                Assert.Equal(remoteCertificate, client.RemoteCertificate);
        }

        [Fact]
        public async Task TestConnectionBasic()
        {
            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            //verify reads
            await VerifyRead(client, server.Client, clientMessage);
            await VerifyRead(server.Client, client, serverMessage);

            //dispose client/server client
            await DisposeConnections(client, server);
        }

        [Fact]
        public async Task TestSSLConnectionBasic()
        {
            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            //enable encryption
            await Task.WhenAll(client.AuthenticateAsClientAsync(), server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey));

            //verify TLS enabled
            VerifyEncryptionEnabled(client, this.ctx.ServerCertificate);
            VerifyEncryptionEnabled(server.Client);

            //verify reads
            await VerifyRead(client, server.Client, clientMessage);
            await VerifyRead(server.Client, client, serverMessage);

            //dispose client/server client
            await DisposeConnections(client, server);
        }

        [Fact]
        public async Task TestSSLConnectionThreadedRead()
        {
            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            CancellationTokenSource readCancel = new CancellationTokenSource();
            TaskCompletionSource<ReadResult> readCorrectServerMessage = new TaskCompletionSource<ReadResult>();
            TaskCompletionSource<ReadResult> readCorrectClientMessage = new TaskCompletionSource<ReadResult>();
            ReadResult clientResult, serverResult;

            Task clientReadTask = Task.Run(async () =>
            {
                ValueTask<ReadResult> readResultTask;
                ReadResult currentReadResult;
                do
                {
                    readResultTask = default;
                    try
                    {
                        readResultTask = client.Input.ReadAsync(readCancel.Token);
                        if (!readResultTask.IsCompleted)
                            currentReadResult = await readResultTask.ConfigureAwait(false);
                        else
                            currentReadResult = readResultTask.Result;
                    }
                    catch (Exception)
                    {
                        if (readCancel.IsCancellationRequested)
                            break;
                        throw;
                    }

                    readCorrectServerMessage.SetResult(currentReadResult);
                } while ((!readCancel.IsCancellationRequested));
            });

            Task serverReadTask = Task.Run(async () =>
            {
                ValueTask<ReadResult> readResultTask;
                ReadResult currentReadResult;
                do
                {
                    readResultTask = default;
                    try
                    {
                        readResultTask = server.Client.Input.ReadAsync(readCancel.Token);
                        if (!readResultTask.IsCompleted)
                            currentReadResult = await readResultTask.ConfigureAwait(false);
                        else
                            currentReadResult = readResultTask.Result;
                    }
                    catch (Exception)
                    {
                        if(readCancel.IsCancellationRequested)
                            break;
                        throw;
                    }

                    readCorrectClientMessage.SetResult(currentReadResult);
                } while ((!readCancel.IsCancellationRequested));
            });

            //unencrypted write from server to client
            await server.Client.Output.WriteAsync(serverMessage);
            clientResult = await readCorrectServerMessage.Task;
            Assert.True(clientResult.Buffer.First.Span.SequenceEqual(serverMessage));
            client.Input.AdvanceTo(clientResult.Buffer.End);

            //TODO: can not reverse, client path too (?) synchronous
            Task serverAuthenticate = server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey);
            Task clientAuthenticate = client.AuthenticateAsClientAsync();

            //enable encryption
            await Task.WhenAll(clientAuthenticate, serverAuthenticate);

            //check if encryption enabled
            VerifyEncryptionEnabled(client, this.ctx.ServerCertificate);
            VerifyEncryptionEnabled(server.Client);

            //encrypted write from client to server
            await client.Output.WriteAsync(clientMessage);
            serverResult = await readCorrectClientMessage.Task;
            Assert.True(serverResult.Buffer.First.Span.SequenceEqual(clientMessage));
            server.Client.Input.AdvanceTo(serverResult.Buffer.End);

            readCancel.Cancel();
            await Task.WhenAll(clientReadTask, serverReadTask);

            //dispose client/server client
            await DisposeConnections(client, server);
        }

        [Fact]
        public async Task TestSSLConnectionSession()
        {
            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            //enable encryption
            await Task.WhenAll(client.AuthenticateAsClientAsync(), server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey));

            //verify if encryption is enabled
            VerifyEncryptionEnabled(client, this.ctx.ServerCertificate);
            VerifyEncryptionEnabled(server.Client);

            //verify reads
            await VerifyRead(client, server.Client, clientMessage);
            await VerifyRead(server.Client, client, serverMessage);

            //shutdown client socket
            client.Socket.Shutdown(SocketShutdown.Receive);
            client.Socket.Shutdown(SocketShutdown.Send);
            //shutdown server socket
            server.Client.Socket.Shutdown(SocketShutdown.Receive);
            server.Client.Socket.Shutdown(SocketShutdown.Send);

            //reset client connection and dispose server
            await Task.WhenAll(client.Reset(), Task.Run(server.Dispose));

            //reconnect client
            await client.ConnectAsync(this.serverListener.Listener.LocalEndPoint);

            //get new server client
            server = serverListener.GetNextClient();

            //re-authenticate client/server with session reuse
            await Task.WhenAll(client.AuthenticateAsClientAsync(), server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey));

            //verify if encryption is enabled
            VerifyEncryptionEnabled(client, this.ctx.ServerCertificate);
            VerifyEncryptionEnabled(server.Client);

            //check for session reuse
            Assert.True(client.SessionReused);

            //verify reads
            await VerifyRead(client, server.Client, clientMessage);
            await VerifyRead(server.Client, client, serverMessage);

            //dispose client/server client
            await DisposeConnections(client, server);
        }

        [Fact]
        public async Task TestSSLVerificationCallback()
        {
            bool validationCalled = false;

            RemoteCertificateValidationHandler validate = new RemoteCertificateValidationHandler(
                (bool preVerifySucceeded, X509Certificate cert, IReadOnlyCollection<X509Certificate> certList) =>
            {
                Assert.Equal(cert, this.ctx.ServerCertificate);
                validationCalled = true;
                return true;
            });

            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            //enable encryption
            await Task.WhenAll(
                client.AuthenticateAsClientAsync(validate), 
                server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey)
            );

            //verify if encryption is enabled
            VerifyEncryptionEnabled(client, this.ctx.ServerCertificate);
            VerifyEncryptionEnabled(server.Client);

            //verify if validation callback was called
            Assert.True(validationCalled);

            //verify reads
            await VerifyRead(client, server.Client, clientMessage);
            await VerifyRead(server.Client, client, serverMessage);

            //dispose client/server client
            await DisposeConnections(client, server);
        }

        [Fact]
        public async Task TestSSLVerification()
        {
            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            //create CA chain to to verify server certificate
            OpenSslList<X509Certificate> caChain = new OpenSslList<X509Certificate>();
            caChain.Add(this.ctx.CACertificate);

            //enable encryption
            await Task.WhenAll(
                client.AuthenticateAsClientAsync(caChain),
                server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey)
            );

            //verify if encryption is enabled
            VerifyEncryptionEnabled(client, this.ctx.ServerCertificate);
            VerifyEncryptionEnabled(server.Client);

            //verify reads
            await VerifyRead(client, server.Client, clientMessage);
            await VerifyRead(server.Client, client, serverMessage);

            //dispose client/server client
            await DisposeConnections(client, server);
        }

        [Fact]
        public async Task TestSSLClientCertificateCallback()
        {
            bool clientCallbackCalled = false;

            ClientCertificateCallbackHandler clientCertCallback = new ClientCertificateCallbackHandler(
                (IReadOnlyCollection<X509Name> validCA,
                    out X509Certificate clientCertificate,
                    out PrivateKey clientPrivateKey) =>
                {
                    Assert.NotEmpty(validCA);

                    using (X509Name clientValidName = validCA.First())
                    {
                        Assert.NotNull(clientValidName);
                        Assert.Equal("Root", clientValidName.Common);
                    }

                    clientCertificate = this.ctx.ClientCertificate;
                    clientPrivateKey = this.ctx.ClientKey;

                    return (clientCallbackCalled = true);
                });

            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            //create CA chain to to verify client certificate
            OpenSslList<X509Certificate> caChain = new OpenSslList<X509Certificate>();
            caChain.Add(this.ctx.CACertificate);

            //enable encryption
            await Task.WhenAll(
                client.AuthenticateAsClientAsync(clientCertCallback), 
                server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey, caChain));

            //verify if encryption is enabled
            VerifyEncryptionEnabled(client, this.ctx.ServerCertificate);
            VerifyEncryptionEnabled(server.Client, this.ctx.ClientCertificate);

            //verify if client certificate callback was called
            Assert.True(clientCallbackCalled);

            //verify reads
            await VerifyRead(client, server.Client, clientMessage);
            await VerifyRead(server.Client, client, serverMessage);

            //dispose client/server client
            await DisposeConnections(client, server);
        }

        [Fact]
        public async Task TestSSLClientCertificate()
        {
            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            //create CA chain to to verify client certificate
            OpenSslList<X509Certificate> caChain = new OpenSslList<X509Certificate>();
            caChain.Add(this.ctx.CACertificate);

            //enable encryption
            await Task.WhenAll(
                client.AuthenticateAsClientAsync(this.ctx.ClientCertificate, this.ctx.ClientKey),
                server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey, caChain));

            //verify if encryption is enabled
            VerifyEncryptionEnabled(client, this.ctx.ServerCertificate);
            VerifyEncryptionEnabled(server.Client, this.ctx.ClientCertificate);

            //verify reads
            await VerifyRead(client, server.Client, clientMessage);
            await VerifyRead(server.Client, client, serverMessage);

            //dispose client/server client
            await DisposeConnections(client, server);
        }

        [Fact]
        public async Task TestConnectionBigData()
        {
            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            ValueTask<FlushResult> flushResult;
            ValueTask<ReadResult> clientResult;
            ReadResult readResult;
            long read = 0;
            int position, currentInput = 0;
            int bufferSize = 1024 * 1024 * 4;
            Memory<byte> buffer;

            while (read < 1024 * 1024 * 1024)
            {
                buffer = server.Client.Output.GetMemory(bufferSize);
                Interop.Random.PseudoBytes(buffer.Span);
                server.Client.Output.Advance(buffer.Length);

                flushResult = server.Client.Output.FlushAsync();
                if (!flushResult.IsCompleted)
                    await flushResult.ConfigureAwait(false);

                currentInput = 0;
                while (currentInput < buffer.Length)
                {
                    clientResult = client.Input.ReadAsync();
                    if (!clientResult.IsCompleted)
                        readResult = await clientResult.ConfigureAwait(false);
                    else
                        readResult = clientResult.Result;

                    position = 0;
                    foreach (ReadOnlyMemory<byte> buf in readResult.Buffer)
                    {
                        Assert.True(buf.Span.SequenceEqual(buffer.Span.Slice(currentInput + position, buf.Length)));
                        position += buf.Length;
                    }

                    read += readResult.Buffer.Length;
                    currentInput += (int)readResult.Buffer.Length;
                    client.Input.AdvanceTo(readResult.Buffer.End);
                }
            }

            await DisposeConnections(client, server);
        }

        [Fact]
        public async Task TestSSLConnectionBigData()
        {
            //connect to server
            SocketConnection client = await CreateClient(this.serverListener);

            //get client from server
            ClientWrapper server = this.serverListener.GetNextClient();

            //enable encryption
            await Task.WhenAll(client.AuthenticateAsClientAsync(), server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey));

            //verify TLS enabled
            VerifyEncryptionEnabled(client, this.ctx.ServerCertificate);
            VerifyEncryptionEnabled(server.Client);

            ValueTask<FlushResult> flushResultTask;
            ValueTask<ReadResult> readResultTask;
            ReadResult readResult;
            FlushResult flushResult;
            long read = 0;
            int position, currentInput = 0;
            int bufferSize = 1024 * 1024 * 4;
            Memory<byte> buffer;

            while (read < 1024 * 1024 * 1024)
            {
                buffer = server.Client.Output.GetMemory(bufferSize);
                Interop.Random.PseudoBytes(buffer.Span);
                server.Client.Output.Advance(buffer.Length);

                flushResultTask = server.Client.Output.FlushAsync();
                if (!flushResultTask.IsCompleted)
                    flushResult = await flushResultTask.ConfigureAwait(false);

                currentInput = 0;
                while (currentInput < buffer.Length)
                {
                    readResultTask = client.Input.ReadAsync();
                    if (!readResultTask.IsCompleted)
                        readResult = await readResultTask.ConfigureAwait(false);
                    else
                        readResult = readResultTask.Result;

                    position = 0;
                    foreach (ReadOnlyMemory<byte> buf in readResult.Buffer)
                    {
                        Assert.True(buf.Span.SequenceEqual(buffer.Span.Slice(currentInput + position, buf.Length)));
                        position += buf.Length;
                    }

                    read += readResult.Buffer.Length;
                    currentInput += (int)readResult.Buffer.Length;
                    client.Input.AdvanceTo(readResult.Buffer.End);
                }
            }

            await DisposeConnections(client, server);
        }
    }

    internal class SslTestContext : IDisposable
    {
        private X509Certificate caCertificate;
        public X509Certificate CACertificate => this.caCertificate;
        public PrivateKey CAKey => this.caCertificate.PublicKey;

        public X509Certificate ServerCertificate { get; private set; }
        public PrivateKey ServerKey => this.ServerCertificate.PublicKey;

        public X509Certificate ClientCertificate { get; private set; }
        public PrivateKey ClientKey => this.ClientCertificate.PublicKey;

        internal SslTestContext()
        {
            X509CertificateAuthority ca = X509CertificateAuthority.CreateX509CertificateAuthority(
                1024,
                "Root",
                "Root",
                DateTime.Now,
                DateTime.Now + TimeSpan.FromDays(365),
                out this.caCertificate);

            this.ServerCertificate = CreateCertificate(ca, "server");
            this.ClientCertificate = CreateCertificate(ca, "client");
        }

        private X509Certificate CreateCertificate(X509CertificateAuthority ca, string name)
        {
            DateTime start = DateTime.Now;
            DateTime end = start + TimeSpan.FromDays(365);
            X509Certificate cert;

            using (RSAKey rsaKey = new RSAKey(1024))
            {
                rsaKey.GenerateKey();
                using (X509CertificateRequest req = new X509CertificateRequest(rsaKey, name, name))
                    cert = ca.ProcessRequest(req, start, end, DigestType.SHA256);
            }

            return cert;
        }

        #region IDisposable implementation

        public void Dispose()
        {
            this.ServerCertificate.Dispose();
            this.ClientCertificate.Dispose();
            this.CACertificate.Dispose();
        }

        #endregion
    }

    internal class ClientWrapper : IDisposable
    {
        internal SocketConnection Client { get; private set; }
        internal TaskCompletionSource<bool> End { get; private set; }

        internal ClientWrapper(SocketConnection client)
        {
            this.Client = client;
            this.End = new TaskCompletionSource<bool>();
        }

        public void Dispose()
        {
            this.End.SetResult(true);
        }
    }

    internal class SocketServerImplementation : SocketServer
    {
        private ConcurrentQueue<ClientWrapper> clientQueue;
        private AutoResetEvent signal;

        internal SocketServerImplementation()
            : base()
        {
            this.clientQueue = new ConcurrentQueue<ClientWrapper>();
            this.signal = new AutoResetEvent(false);
        }

        public ClientWrapper GetNextClient()
        {
            this.signal.WaitOne();

            if (!this.clientQueue.TryDequeue(out ClientWrapper client))
                throw new ArgumentNullException("Client not found");

            try
            {
                return client;
            }
            finally
            {
                this.signal.Reset();
            }
        }

        protected override Task OnClientConnectedAsync(in ClientConnection client)
        {
            ClientWrapper clientWrapper = new ClientWrapper(client.SocketConnection);

            this.clientQueue.Enqueue(clientWrapper);
            this.signal.Set();

            return clientWrapper.End.Task;
        }

        protected override void Dispose(bool disposing)
        {
            this.signal.Dispose();
            base.Dispose(disposing);
        }
    }
}
