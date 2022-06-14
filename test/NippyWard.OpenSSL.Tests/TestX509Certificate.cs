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

using NippyWard.OpenSSL.ASN1;
using NippyWard.OpenSSL.Keys;
using NippyWard.OpenSSL.X509;
using NippyWard.OpenSSL.Collections;
using NippyWard.OpenSSL.Error;

namespace NippyWard.OpenSSL.Tests
{
	public class TestX509Certificate : TestBase
	{
        public TestX509Certificate(ITestOutputHelper outputHelper)
            : base(outputHelper) { }

        protected override void Dispose(bool disposing) { }

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
                using (var cert = new X509Certificate(key, "localhost", "localhost", start, end))
                {
                    cert.SelfSign(key, DigestType.SHA256);
                }
            }
        }

        [Fact]
        public void CanVerifyPrivateKey()
        {
            var start = DateTime.Now;
            var end = start + TimeSpan.FromMinutes(10);
            using (RSAKey key = new RSAKey(1024))
            {
                using (var cert = new X509Certificate(key, "localhost", "localhost", start, end))
                {
                    Assert.True(cert.VerifyPrivateKey(key));

                    using (DSAKey other = new DSAKey(32))
                    {
                        Assert.Throws<OpenSslException>(() => cert.VerifyPrivateKey(other));
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
                using (var cert = new X509Certificate(key, "localhost", "localhost", start, end))
                {
                    cert.Sign(key, DigestType.SHA256);
                    Assert.True(cert.VerifyPublicKey(key));

                    using (RSAKey other = new RSAKey(1024))
                    {
                        Assert.Throws<OpenSslException>(() => cert.VerifyPublicKey(other));
                    }
                }
            }
        }

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
                out X509Certificate caCert);

            //verify if correct CA
            caCert.VerifyPrivateKey(ca.Key);
            caCert.VerifyPublicKey((IPublicKey)caCert.PublicKey);

            using (ca)
            {
                using (caCert)
                {
                    using (RSAKey key = new RSAKey(1024))
                    {
                        using (X509CertificateRequest req = new X509CertificateRequest(key, "localhost", "root"))
                        {
                            //sign the request with itself
                            req.Sign(key, DigestType.SHA256);

                            Assert.Equal("localhost", req.OrganizationUnit);
                            Assert.Equal("root", req.Common);

                            //verify if signing succeeded
                            req.VerifyPrivateKey(key);
                            req.VerifyPublicKey((IPublicKey)req.PublicKey);

                            using (X509Certificate cert = ca.ProcessRequest(req, start, end))
                            {
                                //TODO: add custom extensions before sign

                                //sign new certificate with CA
                                ca.Sign(cert, DigestType.SHA256);

                                Assert.Equal(1, cert.SerialNumber);
                                Assert.Equal("root", cert.Common);
                                Assert.Equal("localhost", cert.OrganizationUnit);

                                Assert.True(cert.VerifyPrivateKey(key));
                                Assert.True(cert.VerifyPublicKey((IPublicKey)caCert.PublicKey));
                            }
                        }
                    }
                }
            }
        }

        [Fact]
        public void CanVerifyCertificateFromStore()
        {
            var start = DateTime.Now;
            var end = start + TimeSpan.FromMinutes(10);

            X509CertificateAuthority ca = X509CertificateAuthority.CreateX509CertificateAuthority
            (
                1024,
                "root",
                "root",
                start,
                end,
                out X509Certificate caCert
            );

            //verify if correct CA
            caCert.VerifyPrivateKey(ca.Key);
            caCert.VerifyPublicKey((IPublicKey)caCert.PublicKey);

            using (ca)
            {
                using (RSAKey key = new RSAKey(1024))
                {
                    using (X509CertificateRequest req = new X509CertificateRequest(key, "localhost", "root"))
                    {
                        //sign the request with itself
                        req.Sign(key, DigestType.SHA256);

                        Assert.Equal("localhost", req.OrganizationUnit);
                        Assert.Equal("root", req.Common);

                        //verify if signing succeeded
                        req.VerifyPrivateKey(key);
                        req.VerifyPublicKey((IPublicKey)req.PublicKey);

                        using (X509Certificate cert = ca.ProcessRequest(req, start, end))
                        {
                            //sign new certificate with CA
                            ca.Sign(cert, DigestType.SHA256);

                            Assert.Equal(1, cert.SerialNumber);
                            Assert.Equal("root", cert.Common);
                            Assert.Equal("localhost", cert.OrganizationUnit);

                            Assert.True(cert.VerifyPrivateKey(key));
                            Assert.True(cert.VerifyPublicKey((IPublicKey)caCert.PublicKey));

                            using (X509Store store = new X509Store(new X509Certificate[] { caCert }))
                            {
                                Assert.True(store.Verify(cert, out VerifyResult verifyResult));
                            }
                        }
                    }
                }
            }
        }

        [Fact]
        public void CanAddExtensions()
        {
            var extList = new List<Tuple<X509ExtensionType, string>> {
                            Tuple.Create(X509ExtensionType.BasicConstraints,  "CA:true"),
                            Tuple.Create(X509ExtensionType.KeyUsage, "cRLSign,keyCertSign"),
                  };

            var start = DateTime.Now;
            var end = start + TimeSpan.FromMinutes(10);
            using (RSAKey key = new RSAKey(1024))
            {
                using (X509Certificate cert = new X509Certificate(key, "root", "root", start, end))
                {
                    foreach (var tuple in extList)
                    {
                        cert.AddX509Extension(tuple.Item1, tuple.Item2);
                    }

                    Assert.NotEmpty(cert);

                    int count = 0;
                    foreach (X509Extension ext in cert)
                    {
                        count++;
                        Assert.NotNull(ext);
                        Assert.NotEmpty(ext.Data);
                    }

                    Assert.Equal(2, count);
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
                using (IOpenSslReadOnlyCollection<X509Certificate> caCerts = caStore.GetCertificates())
                {
                    Assert.NotEmpty(caCerts);
                }
            }
        }

        [Fact]
        public void CanInitializeCAStoreFromList()
        {
            FileInfo caFile = new FileInfo("certs/cacert-20190414.pem");
            Assert.True(caFile.Exists);

            using (IOpenSslReadOnlyCollection<X509Certificate> certificates = X509CertificateReader.ImportPEM(caFile))
            {
                Assert.NotNull(certificates);
                Assert.NotEmpty(certificates);

                using (X509Store caStore = new X509Store(certificates))
                {
                    using (IOpenSslReadOnlyCollection<X509Certificate> caCerts = caStore.GetCertificates())
                    {
                        Assert.NotEmpty(caCerts);
                    }
                }
            }
        }
    }
}
