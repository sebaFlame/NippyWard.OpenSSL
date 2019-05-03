// Copyright (c) 2009-2010 Frank Laub
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
using System.IO;
using System.Collections.Generic;
using System.Linq;

using Xunit;
using Xunit.Abstractions;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Keys;
using OpenSSL.Core.X509;
using OpenSSL.Core.Collections;

namespace OpenSSL.Core.Tests
{
	public class TestX509Certificate : TestBase
	{
        public TestX509Certificate(ITestOutputHelper outputHelper)
            : base(outputHelper) { }

        [Fact]
		public void CanCreateAndDispose()
		{
            X509Certificate cert = new X509Certificate(1024);
            cert.Dispose();
		}

		[Fact]
		public void CanLoadFromPEM()
		{
            using (X509Certificate cert = X509Certificate.Read("certs/ca.crt", "", FileEncoding.PEM))
            {
                Assert.NotNull(cert);
                Assert.Equal("Root", cert.Common);
                Assert.Equal(1234, cert.SerialNumber);
            }
		}

		[Fact]
		public void CanLoadFromDER()
		{
            using (X509Certificate cert = X509Certificate.Read("certs/ca.der", "", FileEncoding.DER))
            {
                Assert.NotNull(cert);
                Assert.Equal("Root", cert.Common);
                Assert.Equal(1234, cert.SerialNumber);
            }
        }

		[Fact]
		public void CanLoadFromPKCS12()
		{
            using (X509Certificate cert = X509Certificate.Read("certs/server.pfx", "p@ssw0rd", FileEncoding.PKCS12))
            {
                Assert.NotNull(cert);
                Assert.Equal("localhost", cert.Common);
                Assert.Equal(1235, cert.SerialNumber);
            }
        }

		[Fact]
		public void CanCreateWithArgs()
		{
			DateTime start = DateTime.Now;
            DateTime end = start + TimeSpan.FromMinutes(10);
			using (RSAKey key = new RSAKey(2048))
            {
                key.GenerateKey();
                using (X509Certificate cert = new X509Certificate(key, "localhost", "localhost", start, end))
                {
                    Assert.Equal("localhost", cert.Common);
                    Assert.Equal("localhost", cert.OrganizationUnit);

                    // We compare short date/time strings here because the wrapper can't handle milliseconds
                    Assert.Equal(start.ToString("d"), cert.NotBefore.ToString("d"));
                    Assert.Equal(end.ToString("d"), cert.NotAfter.ToString("d"));
                }
            }
		}

		[Fact]
		public void CanGetAndSetProperties()
		{
			int serial = 101;
            DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);

            using (RSAKey key = new RSAKey(1024))
            {
                key.GenerateKey();
                int bits = key.Bits;

                using (X509Certificate cert = new X509Certificate(key, "localhost", "localhost", start, end))
                {
                    cert.SerialNumber = serial;
                    cert.NotBefore = start;
                    cert.NotAfter = end;

                    Assert.Equal("localhost", cert.Common);
                    Assert.Equal("localhost", cert.OrganizationUnit);
                    Assert.Equal(serial, cert.SerialNumber);

                    // If the original key gets disposed before the internal private key,
                    // make sure that memory is correctly managed
                    key.Dispose();

                    // If the internal private key has already been disposed, this will blowup
                    Assert.Equal(bits, cert.PublicKey.Bits);

                    // We compare short date/time strings here because the wrapper can't handle milliseconds
                    Assert.Equal(start.ToString("d"), cert.NotBefore.ToString("d"));
                    Assert.Equal(end.ToString("d"), cert.NotAfter.ToString("d"));
                }
            }
		}

        [Fact]
		public void CanCompare()
		{
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);

			using (RSAKey key = new RSAKey(1024))
            {
                key.GenerateKey();
                using (X509Certificate cert = new X509Certificate(key, "localhost", "Root", start, end))
                {
                    cert.SerialNumber = 101;
                    Assert.Equal(cert, cert);

                    using (X509Certificate cert2 = new X509Certificate(key, "localhost", "Root", start, end))
                    {
                        cert.SerialNumber = 101;
                        Assert.NotEqual(cert, cert2);
                    }
                }
            }
		}

		[Fact]
		public void CanSaveAsPEM()
		{
            using (X509Certificate certRead = X509Certificate.Read("certs/ca.crt", "", FileEncoding.PEM))
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    certRead.Write(ms, "", CipherType.NONE, FileEncoding.PEM);

                    ms.Seek(0, SeekOrigin.Begin);

                    using (X509Certificate certWritten = X509Certificate.Read(ms, "", FileEncoding.PEM))
                    {
                        Assert.Equal(certRead, certWritten);
                    }
                }
            }
		}

        [Fact]
        public void CanSaveAsDER()
        {
            using (FileStream fs = new FileStream("certs/ca.der", FileMode.Open))
            {
                using (X509Certificate cert = X509Certificate.Read(fs, "", FileEncoding.DER))
                {
                    fs.Seek(0, SeekOrigin.Begin);

                    using (MemoryStream ms = new MemoryStream())
                    {
                        cert.Write(ms, "", CipherType.NONE, FileEncoding.DER);

                        byte[] bufFs = new byte[1024];
                        byte[] bufMs = new byte[1024];
                        int read;

                        ms.Seek(0, SeekOrigin.Begin);
                        fs.Seek(0, SeekOrigin.Begin);

                        while ((read = fs.Read(bufFs, 0, 1024)) > 0)
                        {
                            Assert.Equal(read, ms.Read(bufMs, 0, read));
                            for (int i = 0; i < read; i++)
                                Assert.Equal(bufFs[i], bufMs[i]);

                            Array.Clear(bufFs, 0, bufFs.Length);
                            Array.Clear(bufMs, 0, bufFs.Length);
                        }
                    }
                }
            }
        }

		[Fact]
		public void CanSign()
		{
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (RSAKey key = new RSAKey(1024))
            {
                key.GenerateKey();
                using (var cert = new X509Certificate(key, "localhost", "localhost", start, end))
                    cert.SelfSign(key, DigestType.SHA256);
            }
		}

		[Fact]
		public void CanVerifyPrivateKey()
		{
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (RSAKey key = new RSAKey(1024))
            {
                key.GenerateKey();
                using (var cert = new X509Certificate(key, "localhost", "localhost", start, end))
                {
                    Assert.True(cert.VerifyPrivateKey(key));

                    using (DSAKey other = new DSAKey(32))
                    {
                        other.GenerateKey();
                        Assert.False(cert.VerifyPrivateKey(other));
                    }
                }
            }

		}

		[Fact]
		public void CanVerifyPublicKey()
		{
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
            using (RSAKey key = new RSAKey(1024))
            {
                key.GenerateKey();
                using (var cert = new X509Certificate(key, "localhost", "localhost", start, end))
                {
                    cert.Sign(key, DigestType.SHA256);
                    Assert.True(cert.VerifyPublicKey(key));

                    using (RSAKey other = new RSAKey(1024))
                    {
                        other.GenerateKey();
                        Assert.False(cert.VerifyPublicKey(other));
                    }
                }
            }

		}

        //TODO: verify signatures
		[Fact]
		public void CanCreateSignedRequest()
		{
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);

            X509CertificateAuthority ca = X509CertificateAuthority.CreateX509CertificateAuthority(
                1024,
                "root",
                "root",
                start,
                end,
                out PrivateKey caKey,
                out X509Certificate caCert);

            using (caKey)
            {
                using (caCert)
                {
                    using (X509CertificateRequest req = new X509CertificateRequest(caKey, "localhost", "root"))
                    {
                        using (X509Certificate cert = ca.ProcessRequest(req, start, end, DigestType.SHA256))
                        {
                            Assert.True(cert.VerifyPrivateKey(caKey));
                            Assert.Equal(1, cert.SerialNumber);
                            Assert.Equal("root", cert.Common);
                            Assert.Equal("localhost", cert.OrganizationUnit);
                        }
                    }
                }
            }
		}

		[Fact]
		public void CanAddExtensions()
		{
			var extList = new List<Tuple<string, bool, string>> {
				Tuple.Create("subjectKeyIdentifier", false, "hash"),
                Tuple.Create("authorityKeyIdentifier", false, "keyid:always,issuer:always"),
                Tuple.Create("X509v3 Basic Constraints", true, "critical,CA:true"),
                Tuple.Create("keyUsage", false, "cRLSign,keyCertSign"),
			};

			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
            using (RSAKey key = new RSAKey(1024))
            {
                key.GenerateKey();
                using (X509Certificate cert = new X509Certificate(key, "root", "root", start, end))
                {
                    foreach(var tuple in extList)
                        cert.AddX509Extension(tuple.Item1, tuple.Item2, tuple.Item3);

                    int index = 0;
                    foreach (X509Extension ext in cert)
                    {
                        Assert.Equal(extList[index].Item3, ext.Data);
                        index++;
                    }
                }
            }
		}

        [Fact]
        public void CanInitializeCAStoreFromFile()
        {
            FileInfo caFile = new FileInfo("certs/cacert-20190414.pem");
            Assert.True(caFile.Exists);

            using (X509Store caStore = new X509Store(caFile))
            {
                using (OpenSslReadOnlyCollection<X509Certificate> caCerts = caStore.GetCertificates())
                {
                    Assert.NotEmpty(caCerts);

                    X509Certificate cert = caCerts.First();
                    foreach(X509Extension ext in cert)
                    {
                        string data = ext.Data;
                    }
                }
            }
        }

        [Fact]
        public void CanInitializeCAStoreFromList()
        {
            FileInfo caFile = new FileInfo("certs/cacert-20190414.pem");
            Assert.True(caFile.Exists);

            using (X509CertificateReader reader = new X509CertificateReader(caFile))
            {
                Assert.NotNull(reader.Certificates);
                Assert.NotEmpty(reader.Certificates);

                using (X509Store caStore = new X509Store(reader.Certificates))
                {
                    using (OpenSslReadOnlyCollection<X509Certificate> caCerts = caStore.GetCertificates())
                        Assert.NotEmpty(caCerts);
                }
            }
        }
    }
}
