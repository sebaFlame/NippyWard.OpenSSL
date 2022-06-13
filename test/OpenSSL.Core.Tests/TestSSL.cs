﻿// Copyright (c) 2009 Ben Henderson
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
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Linq;
using Xunit;
using OpenSSL;
using OpenSSL.Core.Core;
using OpenSSL.Core.X509;
using OpenSSL.Core.SSL;
using OpenSSL.Core.Crypto;
using System.Diagnostics;

namespace OpenSSL.Core.Tests
{
	public class SslTestContext : IDisposable
	{
		public SslTestContext()
		{
			using (var cfg = new Configuration("openssl.cnf"))
			using (var ca = X509CertificateAuthority.SelfSigned(
								cfg,
								new SimpleSerialNumber(),
								"Root",
								DateTime.Now,
								TimeSpan.FromDays(365)))
			{
				CAChain.Add(ca.Certificate);

				ServerCertificate = CreateCertificate(ca, "server", cfg, "tls_server");
				ClientCertificate = CreateCertificate(ca, "client", cfg, "tls_client");
			}

			ClientCertificateList.Add(ClientCertificate);
		}

		X509Certificate CreateCertificate(X509CertificateAuthority ca, string name, Configuration cfg, string section)
		{
			var now = DateTime.Now;
			var future = now + TimeSpan.FromDays(365);

			using (var subject = new X509Name(name))
			using (var rsa = new RSA())
			{
				rsa.GenerateKeys(1024, BigNumber.One, null, null);
				using (var key = new CryptoKey(rsa))
				{
					var request = new X509Request(1, subject, key);
					var cert = ca.ProcessRequest(request, now, future, cfg, section);
					cert.PrivateKey = key;
					return cert;
				}
			}
		}

		public X509Chain CAChain = new X509Chain();
		public X509List ClientCertificateList = new X509List();
		public X509Certificate ServerCertificate;
		public X509Certificate ClientCertificate;

		#region IDisposable implementation

		public void Dispose()
		{
			ClientCertificateList.Clear();
			CAChain.Dispose();
			ServerCertificate.Dispose();
			ClientCertificate.Dispose();
		}

		#endregion
	}

	public class TestSSL : TestBase
	{
		SslTestContext _ctx;
		static byte[] clientMessage = Encoding.ASCII.GetBytes("This is a message from the client");
		static byte[] serverMessage = Encoding.ASCII.GetBytes("This is a message from the server");

		public TestSSL()
            :base()
		{
			Threading.Initialize();
			_ctx = new SslTestContext();
		}

		public override void Dispose()
		{
			_ctx.Dispose();
			Threading.Cleanup();
			base.Dispose();
		}

		[Fact]
		public void TestSslCipherList()
		{
			Assert.Equal("LOW:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.None, SslStrength.Low)
			);

			Assert.Equal("MEDIUM:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.None, SslStrength.Medium)
			);

			Assert.Equal("HIGH:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.None, SslStrength.High)
			);

			Assert.Equal("HIGH:MEDIUM:LOW:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.None, SslStrength.All)
			);

			Assert.Equal("HIGH:MEDIUM:LOW:!SSLv2:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.Default, SslStrength.All)
			);

			Assert.Equal("HIGH:MEDIUM:LOW:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.Ssl2, SslStrength.All)
			);
		}

		[Fact]
		public void TestSyncBasic()
		{
			IPEndPoint ep = null;
			var evtReady = new AutoResetEvent(false);

			var serverTask = Task.Factory.StartNew(() =>
			{
				var listener = new TcpListener(IPAddress.Loopback, 0);
				listener.Start(5);
				ep = (IPEndPoint)listener.LocalEndpoint;

				evtReady.Set();

				Console.WriteLine("Server> waiting for accept");

				using (var tcp = listener.AcceptTcpClientAsync().Result)
				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Server> authenticate");
					sslStream.AuthenticateAsServer(_ctx.ServerCertificate).Wait();

					Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.Equal("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Server> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.Equal(clientMessage.ToString(), buf.ToString());

					Console.WriteLine("Server> tx msg");
					sslStream.Write(serverMessage, 0, serverMessage.Length);

					Console.WriteLine("Server> done");
				}

				listener.Stop();
			});

			var clientTask = Task.Factory.StartNew(() =>
			{
				evtReady.WaitOne();

				Console.WriteLine("Client> Connecting to: {0}:{1}", ep.Address, ep.Port);
                var tcp = new TcpClient();
                tcp.ConnectAsync(ep.Address.ToString(), ep.Port).Wait();

				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Client> authenticate");
					sslStream.AuthenticateAsClient("localhost").Wait();

					Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
                    Debug.WriteLine(string.Format("Client> Current Version: {0}", sslStream.Ssl.SSLVersion().ToString()));
					Assert.Equal("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Client> tx msg");
					sslStream.Write(clientMessage, 0, clientMessage.Length);

					Console.WriteLine("Client> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.Equal(serverMessage.ToString(), buf.ToString());

					Console.WriteLine("Client> done");
				}

                tcp.Dispose();
			});

			serverTask.Wait();
			clientTask.Wait();
		}

		[Fact]
		public void TestSyncIntermediate()
		{
			IPEndPoint ep = null;
			var evtReady = new AutoResetEvent(false);

			var serverTask = Task.Factory.StartNew(() =>
			{
				var listener = new TcpListener(IPAddress.Loopback, 0);
				listener.Start(5);
				ep = (IPEndPoint)listener.LocalEndpoint;

				evtReady.Set();

				Console.WriteLine("Server> waiting for accept");

				using (var tcp = listener.AcceptTcpClientAsync().Result)
				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Server> authenticate");
                    sslStream.AuthenticateAsServer(
                        _ctx.ServerCertificate,
                        false,
                        null,
                        SslProtocols.Default,
                        SslStrength.Low,
                        false,
                        CancellationToken.None
                    ).Wait();

					Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.Equal("DES-CBC-SHA", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Server> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.Equal(clientMessage.ToString(), buf.ToString());

					Console.WriteLine("Server> tx msg");
					sslStream.Write(serverMessage, 0, serverMessage.Length);

					Console.WriteLine("Server> done");
				}

				listener.Stop();
			});

			var clientTask = Task.Factory.StartNew(() =>
			{
				evtReady.WaitOne();

				Console.WriteLine("Client> Connecting to: {0}:{1}", ep.Address, ep.Port);

                var tcp = new TcpClient();

                tcp.ConnectAsync(ep.Address.ToString(), ep.Port).Wait();
				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Client> authenticate");
                    sslStream.AuthenticateAsClient(
                        "localhost",
                        null,
                        null,
                        SslProtocols.Default,
                        SslStrength.Low,
                        false,
                        CancellationToken.None
                    ).Wait();

					Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.Equal("DES-CBC-SHA", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Client> tx msg");
					sslStream.Write(clientMessage, 0, clientMessage.Length);

					Console.WriteLine("Client> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.Equal(serverMessage.ToString(), buf.ToString());

					Console.WriteLine("Client> done");
				}

                tcp.Dispose();
			});

			serverTask.Wait();
			clientTask.Wait();
		}

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

		bool ValidateRemoteCert(
			object obj,
			X509Certificate cert,
			X509Chain chain,
			int depth,
			VerifyResult result)
		{
			Console.WriteLine("Validate> {0} depth: {1}, result: {2}", cert.Subject, depth, result);
			switch (result)
			{
				case VerifyResult.X509_V_ERR_CERT_UNTRUSTED:
				case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
				case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
				case VerifyResult.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
				case VerifyResult.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
					// Check the chain to see if there is a match for the cert
					var ret = CheckCert(cert, chain);
					if (!ret && depth != 0)
					{
						return true;
					}
					return ret;
				case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
				case VerifyResult.X509_V_ERR_CERT_NOT_YET_VALID:
					Console.WriteLine("Certificate is not valid yet");
					return false;
				case VerifyResult.X509_V_ERR_CERT_HAS_EXPIRED:
				case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
					Console.WriteLine("Certificate is expired");
					return false;
				case VerifyResult.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
					// we received a self signed cert - check to see if it's in our store
					return CheckCert(cert, chain);
				case VerifyResult.X509_V_OK:
					return true;
				default:
					return false;
			}
		}

		bool CheckCert(X509Certificate cert, X509Chain chain)
		{
			if (cert == null || chain == null)
				return false;

			foreach (var certificate in chain)
			{
				if (cert == certificate)
					return true;
			}

			return false;
		}

		X509Certificate SelectClientCertificate(
			object sender,
			string targetHost,
			X509List localCerts,
			X509Certificate remoteCert,
			string[] acceptableIssuers)
		{
			Console.WriteLine("SelectClientCertificate> {0}", targetHost);

			foreach (var issuer in acceptableIssuers)
			{
				Console.WriteLine("SelectClientCertificate> issuer: {0}", issuer);

				using (var name = new X509Name(issuer))
				{
					foreach (var cert in localCerts)
					{
						Console.WriteLine("SelectClientCertificate> local: {0}", cert.Subject);
						if (cert.Issuer.CompareTo(name) == 0)
						{
							return cert;
						}
						cert.Dispose();
					}
				}
			}
			return null;
		}
	}
}
