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
using System.Diagnostics;

using Xunit;
using Xunit.Abstractions;

using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using OpenSSL.Core.SSL;
using System.IO.Pipelines;
using OpenSSL.Core.Error;

namespace OpenSSL.Core.Tests
{
    internal class SslTestContext : IDisposable
    {
        private X509Certificate caCert;
        private PrivateKey caKey;

        public SslTestContext()
        {
            this.caKey = new RSAKey(1024);
            this.caKey.GenerateKey();
            this.caCert = new X509Certificate(this.caKey, "Root", "Root", DateTime.Now, DateTime.Now + TimeSpan.FromDays(365));
            this.caCert.SelfSign(this.caKey, DigestType.SHA256);
            //this.CAChain.Add(this.caCert);

            SimpleSerialNumber seq = new SimpleSerialNumber();
            using (X509CertificateAuthority ca = new X509CertificateAuthority(caCert, this.caKey, seq))
            {
                this.ServerCertificate = CreateCertificate(ca, "server", out this.ServerKey);
                this.ClientCertificate = CreateCertificate(ca, "client", out this.ClientKey);
            }

            //ClientCertificateList.Add(ClientCertificate);
        }

        private X509Certificate CreateCertificate(X509CertificateAuthority ca, string name, out PrivateKey privateKey)
        {
            DateTime start = DateTime.Now;
            DateTime end = start + TimeSpan.FromDays(365);
            X509Certificate cert;

            privateKey = new RSAKey(1024);
            privateKey.GenerateKey();
            X509CertificateRequest req = new X509CertificateRequest(privateKey, name, name);
            cert = ca.ProcessRequest(req, start, end, DigestType.SHA256);
                
            //cert.AddX509Extension(extension, true, null);
            return cert;
        }

        //public X509Chain CAChain = new X509Chain();
        //public X509List ClientCertificateList = new X509List();
        public X509Certificate ServerCertificate;
        public PrivateKey ServerKey;

        public X509Certificate ClientCertificate;
        public PrivateKey ClientKey;

        #region IDisposable implementation

        public void Dispose()
        {
            //ClientCertificateList.Clear();
            //CAChain.Dispose();
            this.ServerCertificate.Dispose();
            this.ServerKey.Dispose();
            this.ClientCertificate.Dispose();
            this.ClientKey.Dispose();
            this.caCert.Dispose();
            this.caKey.Dispose();
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

    public class TestSSL : TestBase
    {
        private SslTestContext ctx;
        static byte[] clientMessage = Encoding.ASCII.GetBytes("This is a message from the client");
        static byte[] serverMessage = Encoding.ASCII.GetBytes("This is a message from the server");

        public TestSSL(ITestOutputHelper outputHelper)
            : base(outputHelper)
        {
            this.ctx = new SslTestContext();
        }

        public override void Dispose()
        {
            this.ctx.Dispose();
        }

        private class SocketServerImplementation : SocketServer
        {
            private ConcurrentQueue<ClientWrapper> clientQueue;
            private AutoResetEvent signal;

            public SocketServerImplementation()
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

        [Fact]
        public async Task TestConnectionBasic()
        {
            ReadResult readResult;

            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Loopback, 0);
            SocketServerImplementation serverListener = new SocketServerImplementation();
            serverListener.Listen(serverEndPoint);

            //connect to server
            IPEndPoint clientEndPoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)serverListener.Listener.LocalEndPoint).Port);
            SocketConnection client = await SocketConnection.ConnectAsync(clientEndPoint);

            //get client from server
            ClientWrapper server = serverListener.GetNextClient();

            await client.Output.WriteAsync(clientMessage);
            ValueTask<ReadResult> clientResult = server.Client.Input.ReadAsync();
            if (!clientResult.IsCompleted)
                readResult = await clientResult.ConfigureAwait(false);
            else
                readResult = clientResult.Result;

            Assert.True(readResult.Buffer.IsSingleSegment);
            Assert.True(readResult.Buffer.First.Span.SequenceEqual(clientMessage));

            await server.Client.Output.WriteAsync(serverMessage);
            ValueTask<ReadResult> serverResult = client.Input.ReadAsync();
            if (!serverResult.IsCompleted)
                readResult = await serverResult.ConfigureAwait(false);
            else
                readResult = serverResult.Result;

            Assert.True(readResult.Buffer.IsSingleSegment);
            Assert.True(readResult.Buffer.First.Span.SequenceEqual(serverMessage));

            await Task.WhenAll(Task.Run(client.Dispose), Task.Run(server.Client.Dispose));

            server.Dispose();
            serverListener.Dispose();
        }

        [Fact]
        public async Task TestSSLConnectionBasic()
        {
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Loopback, 0);
            SocketServerImplementation serverListener = new SocketServerImplementation();
            serverListener.Listen(serverEndPoint);

            //connect to server
            IPEndPoint clientEndPoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)serverListener.Listener.LocalEndPoint).Port);
            SocketConnection client = await SocketConnection.ConnectAsync(clientEndPoint, null, SocketConnectionOptions.None ,null, null, "client"); ;

            //get client from server
            ClientWrapper server = serverListener.GetNextClient();

            //enabel encryption
            await Task.WhenAll(client.AuthenticateAsClientAsync(), server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey));

            Assert.NotEmpty(client.Cipher);
            Assert.True(client.Protocol >= SslProtocol.Tls12);

            Assert.NotEmpty(server.Client.Cipher);
            Assert.True(server.Client.Protocol >= SslProtocol.Tls12);

            await client.Output.WriteAsync(clientMessage);
            ReadResult clientResult = await server.Client.Input.ReadAsync();
            //Assert.True(clientResult.Buffer.IsSingleSegment); //TODO: remove extra segment
            Assert.True(clientResult.Buffer.First.Span.SequenceEqual(clientMessage));

            await server.Client.Output.WriteAsync(serverMessage);
            ReadResult serverResult = await client.Input.ReadAsync();
            //Assert.True(serverResult.Buffer.IsSingleSegment); //TODO: remove extra segment
            Assert.True(serverResult.Buffer.First.Span.SequenceEqual(serverMessage));

            await Task.WhenAll(Task.Run(client.Dispose), Task.Run(server.Client.Dispose));
            server.Dispose();
            serverListener.Dispose();
        }

        [Fact]
        public async Task TestSSLConnectionThreadedRead()
        {
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Loopback, 0);
            SocketServerImplementation serverListener = new SocketServerImplementation();
            serverListener.Listen(serverEndPoint);

            IPEndPoint clientEndPoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)serverListener.Listener.LocalEndPoint).Port);
            SocketConnection client = await SocketConnection.ConnectAsync(clientEndPoint, null, SocketConnectionOptions.None, null, null, "client"); ;

            ClientWrapper server = serverListener.GetNextClient();

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
                        if (!currentReadResult.IsCompleted)
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
                        if (!currentReadResult.IsCompleted)
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

            //TODO: can not reverse, client path too (?) synchronous
            Task serverAuthenticate = server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey);
            Task clientAuthenticate = client.AuthenticateAsClientAsync();

            //enable encryption
            await Task.WhenAll(clientAuthenticate, serverAuthenticate);

            //check if encryption enabled
            Assert.NotEmpty(client.Cipher);
            Assert.True(client.Protocol >= SslProtocol.Tls12);
            Assert.NotEmpty(server.Client.Cipher);
            Assert.True(server.Client.Protocol >= SslProtocol.Tls12);

            //encrypted write from client to server
            await client.Output.WriteAsync(clientMessage);
            serverResult = await readCorrectClientMessage.Task;
            Assert.True(serverResult.Buffer.First.Span.SequenceEqual(clientMessage));

            readCancel.Cancel();
            await Task.WhenAll(clientReadTask, serverReadTask);

            await Task.WhenAll(Task.Run(client.Dispose), Task.Run(server.Client.Dispose));
            server.Dispose();
            serverListener.Dispose();
        }

        [Fact]
        public async Task TestSSLConnectionSession()
        {
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Loopback, 0);
            SocketServerImplementation serverListener = new SocketServerImplementation();
            serverListener.Listen(serverEndPoint);

            IPEndPoint clientEndPoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)serverListener.Listener.LocalEndPoint).Port);
            SocketConnection client = await SocketConnection.ConnectAsync(clientEndPoint, null, SocketConnectionOptions.None, null, null, "client"); ;

            ClientWrapper server = serverListener.GetNextClient();

            await Task.WhenAll(client.AuthenticateAsClientAsync(), server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey));

            Assert.NotEmpty(client.Cipher);
            Assert.True(client.Protocol >= SslProtocol.Tls12);

            Assert.NotEmpty(server.Client.Cipher);
            Assert.True(server.Client.Protocol >= SslProtocol.Tls12);

            await client.Output.WriteAsync(clientMessage);
            ReadResult clientResult = await server.Client.Input.ReadAsync();
            //Assert.True(clientResult.Buffer.IsSingleSegment); //TODO: remove extra segment
            Assert.True(clientResult.Buffer.First.Span.SequenceEqual(clientMessage));

            await server.Client.Output.WriteAsync(serverMessage);
            ReadResult serverResult = await client.Input.ReadAsync();
            //Assert.True(serverResult.Buffer.IsSingleSegment); //TODO: remove extra segment
            Assert.True(serverResult.Buffer.First.Span.SequenceEqual(serverMessage));

            //shutdown client socket
            client.Socket.Shutdown(SocketShutdown.Receive);
            client.Socket.Shutdown(SocketShutdown.Send);
            //shutdown server socket
            server.Client.Socket.Shutdown(SocketShutdown.Receive);
            server.Client.Socket.Shutdown(SocketShutdown.Send);

            //task to force read server-side for bi-directional SSL shutdown
            //Task serverRead = Task.Run(async () =>
            //{
            //    ValueTask<ReadResult> readResultTask;
            //    ReadResult currentReadResult;

            //    readResultTask = default;
            //    try
            //    {
            //        readResultTask = server.Input.ReadAsync(CancellationToken.None);
            //        if (!currentReadResult.IsCompleted)
            //            currentReadResult = await readResultTask.ConfigureAwait(false);
            //        else
            //            currentReadResult = readResultTask.Result;
            //    }
            //    catch (AggregateException ag)
            //    {
            //        AggregateException flattened = ag.Flatten();
            //        foreach(Exception ex in flattened.InnerExceptions)
            //        {
            //            if (ex is ShutdownException shutdown)
            //                await server.ShutdownSSL(true);
            //        }
            //    }
            //    catch(Exception ex)
            //    {  }
            //});

            //reset client connection and dispose server
            await Task.WhenAll(client.Reset(), Task.Run(server.Dispose));

            //reconnect client
            await client.ConnectAsync(clientEndPoint);

            //get new server client
            server = serverListener.GetNextClient();

            //re-authenticate client/server with session reuse
            await Task.WhenAll(client.AuthenticateAsClientAsync(), server.Client.AuthenticateAsServerAsync(this.ctx.ServerCertificate, this.ctx.ServerKey));

            //check for session reuse
            Assert.True(client.SessionReused);

            await client.Output.WriteAsync(clientMessage);
            clientResult = await server.Client.Input.ReadAsync();
            //Assert.True(clientResult.Buffer.IsSingleSegment); //TODO: remove extra segment
            Assert.True(clientResult.Buffer.First.Span.SequenceEqual(clientMessage));

            await server.Client.Output.WriteAsync(serverMessage);
            serverResult = await client.Input.ReadAsync();
            //Assert.True(serverResult.Buffer.IsSingleSegment); //TODO: remove extra segment
            Assert.True(serverResult.Buffer.First.Span.SequenceEqual(serverMessage));

            //fully dispose of client/server
            await Task.WhenAll(Task.Run(client.Dispose), Task.Run(server.Client.Dispose));
            server.Dispose();
            serverListener.Dispose();
        }

        //[Fact]
        //public void TestSyncIntermediate()
        //{
        //    IPEndPoint ep = null;
        //    var evtReady = new AutoResetEvent(false);

        //    var serverTask = Task.Factory.StartNew(() =>
        //    {
        //        var listener = new TcpListener(IPAddress.Loopback, 0);
        //        listener.Start(5);
        //        ep = (IPEndPoint)listener.LocalEndpoint;

        //        evtReady.Set();

        //        Console.WriteLine("Server> waiting for accept");

        //        using (var tcp = listener.AcceptTcpClientAsync().Result)
        //        using (var sslStream = new SslStream(tcp.GetStream()))
        //        {
        //            Console.WriteLine("Server> authenticate");
        //            sslStream.AuthenticateAsServer(
        //                ctx.ServerCertificate,
        //                false,
        //                null,
        //                SslProtocols.Default,
        //                SslStrength.Low,
        //                false,
        //                CancellationToken.None
        //            ).Wait();

        //            Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
        //            Assert.Equal("DES-CBC-SHA", sslStream.Ssl.CurrentCipher.Name);

        //            Console.WriteLine("Server> rx msg");
        //            var buf = new byte[256];
        //            sslStream.Read(buf, 0, buf.Length);
        //            Assert.Equal(clientMessage.ToString(), buf.ToString());

        //            Console.WriteLine("Server> tx msg");
        //            sslStream.Write(serverMessage, 0, serverMessage.Length);

        //            Console.WriteLine("Server> done");
        //        }

        //        listener.Stop();
        //    });

        //    var clientTask = Task.Factory.StartNew(() =>
        //    {
        //        evtReady.WaitOne();

        //        Console.WriteLine("Client> Connecting to: {0}:{1}", ep.Address, ep.Port);

        //        var tcp = new TcpClient();

        //        tcp.ConnectAsync(ep.Address.ToString(), ep.Port).Wait();
        //        using (var sslStream = new SslStream(tcp.GetStream()))
        //        {
        //            Console.WriteLine("Client> authenticate");
        //            sslStream.AuthenticateAsClient(
        //                "localhost",
        //                null,
        //                null,
        //                SslProtocols.Default,
        //                SslStrength.Low,
        //                false,
        //                CancellationToken.None
        //            ).Wait();

        //            Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
        //            Assert.Equal("DES-CBC-SHA", sslStream.Ssl.CurrentCipher.Name);

        //            Console.WriteLine("Client> tx msg");
        //            sslStream.Write(clientMessage, 0, clientMessage.Length);

        //            Console.WriteLine("Client> rx msg");
        //            var buf = new byte[256];
        //            sslStream.Read(buf, 0, buf.Length);
        //            Assert.Equal(serverMessage.ToString(), buf.ToString());

        //            Console.WriteLine("Client> done");
        //        }

        //        tcp.Dispose();
        //    });

        //    serverTask.Wait();
        //    clientTask.Wait();
        //}

        //[Fact]
        //[Ignore("Frequent crashes")]
        //public void TestSyncAdvanced()
        //{
        //	IPEndPoint ep = null;
        //	var evtReady = new AutoResetEvent(false);

        //	var serverTask = Task.Factory.StartNew(() =>
        //	{
        //		var listener = new TcpListener(IPAddress.Loopback, 0);
        //		listener.Start(5);
        //		ep = (IPEndPoint)listener.LocalEndpoint;

        //		evtReady.Set();

        //		Console.WriteLine("Server> waiting for accept");

        //		using (var tcp = listener.AcceptTcpClient())
        //		using (var sslStream = new SslStream(tcp.GetStream(), false, ValidateRemoteCert))
        //		{
        //			Console.WriteLine("Server> authenticate");
        //			sslStream.AuthenticateAsServer(
        //				_ctx.ServerCertificate,
        //				true,
        //				_ctx.CAChain,
        //				SslProtocols.Tls,
        //				SslStrength.All,
        //				true
        //			);

        //			Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
        //			Assert.Equal("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);
        //			Assert.IsTrue(sslStream.IsMutuallyAuthenticated);

        //			Console.WriteLine("Server> rx msg");
        //			var buf = new byte[256];
        //			sslStream.Read(buf, 0, buf.Length);
        //			Assert.Equal(clientMessage.ToString(), buf.ToString());

        //			Console.WriteLine("Server> tx msg");
        //			sslStream.Write(serverMessage, 0, serverMessage.Length);

        //			Console.WriteLine("Server> done");
        //		}

        //		listener.Stop();
        //	});

        //	var clientTask = Task.Factory.StartNew(() =>
        //	{
        //		evtReady.WaitOne();

        //		Console.WriteLine("Client> Connecting to: {0}:{1}", ep.Address, ep.Port);

        //		using (var tcp = new TcpClient(ep.Address.ToString(), ep.Port))
        //		using (var sslStream = new SslStream(
        //								   tcp.GetStream(),
        //								   false,
        //								   ValidateRemoteCert,
        //								   SelectClientCertificate))
        //		{
        //			Console.WriteLine("Client> authenticate");
        //			sslStream.AuthenticateAsClient(
        //				"localhost",
        //				_ctx.ClientCertificateList,
        //				_ctx.CAChain,
        //				SslProtocols.Tls,
        //				SslStrength.All,
        //				true
        //			);

        //			Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
        //			Assert.Equal("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);
        //			Assert.IsTrue(sslStream.IsMutuallyAuthenticated);

        //			Console.WriteLine("Client> tx msg");
        //			sslStream.Write(clientMessage, 0, clientMessage.Length);

        //			Console.WriteLine("Client> rx msg");
        //			var buf = new byte[256];
        //			sslStream.Read(buf, 0, buf.Length);
        //			Assert.Equal(serverMessage.ToString(), buf.ToString());

        //			Console.WriteLine("Client> done");
        //		}
        //	});

        //	Task.WaitAll(clientTask, serverTask);
        //}

        //[Fact]
        //public void TestAsyncBasic()
        //{
        //	var listener = new TcpListener(IPAddress.Loopback, 0);
        //	listener.Start(5);
        //	var ep = (IPEndPoint)listener.LocalEndpoint;

        //	Console.WriteLine("Server> waiting for accept");

        //	listener.BeginAcceptTcpClient((IAsyncResult ar) =>
        //	{
        //		var client = listener.EndAcceptTcpClient(ar);

        //		var sslStream = new SslStream(client.GetStream(), false);
        //		Console.WriteLine("Server> authenticate");

        //		sslStream.BeginAuthenticateAsServer(_ctx.ServerCertificate, async (ar2) =>
        //		{
        //			sslStream.EndAuthenticateAsServer(ar2);

        //			Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
        //			Assert.Equal("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

        //			var buf = new byte[256];
        //			await sslStream.ReadAsync(buf, 0, buf.Length);
        //			Assert.Equal(clientMessage.ToString(), buf.ToString());

        //			await sslStream.WriteAsync(serverMessage, 0, serverMessage.Length);

        //			sslStream.Close();
        //			client.Close();

        //			Console.WriteLine("Server> done");
        //		}, null);
        //	}, null);

        //	var evtDone = new AutoResetEvent(false);

        //	var tcp = new TcpClient(AddressFamily.InterNetwork);
        //	tcp.BeginConnect(ep.Address.ToString(), ep.Port, (IAsyncResult ar) =>
        //	{
        //		tcp.EndConnect(ar);

        //		var sslStream = new SslStream(tcp.GetStream());
        //		Console.WriteLine("Client> authenticate");

        //		sslStream.BeginAuthenticateAsClient("localhost", async (ar2) =>
        //		{
        //			sslStream.EndAuthenticateAsClient(ar2);

        //			Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
        //			Assert.Equal("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

        //			await sslStream.WriteAsync(clientMessage, 0, clientMessage.Length);

        //			var buf = new byte[256];
        //			await sslStream.ReadAsync(buf, 0, buf.Length);
        //			Assert.Equal(serverMessage.ToString(), buf.ToString());

        //			sslStream.Close();
        //			tcp.Close();

        //			Console.WriteLine("Client> done");

        //			evtDone.Set();
        //		}, null);
        //	}, null);

        //	evtDone.WaitOne();
        //}

        //bool ValidateRemoteCert(
        //    object obj,
        //    X509Certificate cert,
        //    X509Chain chain,
        //    int depth,
        //    VerifyResult result)
        //{
        //    Console.WriteLine("Validate> {0} depth: {1}, result: {2}", cert.Subject, depth, result);
        //    switch (result)
        //    {
        //        case VerifyResult.X509_V_ERR_CERT_UNTRUSTED:
        //        case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        //        case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        //        case VerifyResult.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        //        case VerifyResult.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        //            // Check the chain to see if there is a match for the cert
        //            var ret = CheckCert(cert, chain);
        //            if (!ret && depth != 0)
        //            {
        //                return true;
        //            }
        //            return ret;
        //        case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        //        case VerifyResult.X509_V_ERR_CERT_NOT_YET_VALID:
        //            Console.WriteLine("Certificate is not valid yet");
        //            return false;
        //        case VerifyResult.X509_V_ERR_CERT_HAS_EXPIRED:
        //        case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        //            Console.WriteLine("Certificate is expired");
        //            return false;
        //        case VerifyResult.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        //            // we received a self signed cert - check to see if it's in our store
        //            return CheckCert(cert, chain);
        //        case VerifyResult.X509_V_OK:
        //            return true;
        //        default:
        //            return false;
        //    }
        //}

        //bool CheckCert(X509Certificate cert, X509Chain chain)
        //{
        //    if (cert == null || chain == null)
        //        return false;

        //    foreach (var certificate in chain)
        //    {
        //        if (cert == certificate)
        //            return true;
        //    }

        //    return false;
        //}

        //X509Certificate SelectClientCertificate(
        //    object sender,
        //    string targetHost,
        //    X509List localCerts,
        //    X509Certificate remoteCert,
        //    string[] acceptableIssuers)
        //{
        //    Console.WriteLine("SelectClientCertificate> {0}", targetHost);

        //    foreach (var issuer in acceptableIssuers)
        //    {
        //        Console.WriteLine("SelectClientCertificate> issuer: {0}", issuer);

        //        using (var name = new X509Name(issuer))
        //        {
        //            foreach (var cert in localCerts)
        //            {
        //                Console.WriteLine("SelectClientCertificate> local: {0}", cert.Subject);
        //                if (cert.Issuer.CompareTo(name) == 0)
        //                {
        //                    return cert;
        //                }
        //                cert.Dispose();
        //            }
        //        }
        //    }
        //    return null;
        //}
    }
}
