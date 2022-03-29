using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.ASN1;

namespace OpenSSL.Core.Tests
{
    public class SslTestContext : IDisposable
    {
        private X509Certificate _caCertificate;
        public X509Certificate CACertificate => this._caCertificate;
        public PrivateKey CAKey => this._caCertificate.PublicKey;

        public X509Certificate ServerCertificate { get; private set; }
        public PrivateKey ServerKey => this.ServerCertificate.PublicKey;

        public X509Certificate ClientCertificate { get; private set; }
        public PrivateKey ClientKey => this.ClientCertificate.PublicKey;

        public SslTestContext()
        {
            X509CertificateAuthority ca = X509CertificateAuthority.CreateX509CertificateAuthority
            (
                2048,
                "Root",
                "Root",
                DateTime.Now,
                DateTime.Now + TimeSpan.FromDays(365),
                out this._caCertificate
            );

            this.ServerCertificate = this.CreateCertificate(ca, "server");
            this.ClientCertificate = this.CreateCertificate(ca, "client");
        }

        private X509Certificate CreateCertificate(X509CertificateAuthority ca, string name)
        {
            DateTime start = DateTime.Now;
            DateTime end = start + TimeSpan.FromDays(365);
            X509Certificate cert;

            //needs 2048 bits for level2 strength
            using (RSAKey rsaKey = new RSAKey(2048))
            {
                rsaKey.GenerateKey();
                using (X509CertificateRequest req = new X509CertificateRequest(rsaKey, name, name))
                {
                    req.Sign(rsaKey, DigestType.SHA256);

                    cert = ca.ProcessRequest(req, start, end);

                    ca.Sign(cert, DigestType.SHA256);
                }
            }

            return cert;
        }

        public void Dispose()
        {
            this.ServerCertificate.Dispose();
            this.ClientCertificate.Dispose();
            this.CACertificate.Dispose();
        }
    }
}
