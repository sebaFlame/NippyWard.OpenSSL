using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;

#nullable enable

namespace OpenSSL.Core.SSL
{
    public class SslOptions
    {
        public SslStrength SslStrength { get; set; }
        public SslProtocol SslProtocol { get; set; }
        public X509Store? CertificateStore { get; set; }
        public X509Certificate? Certificate { get; set; }
        public PrivateKey? PrivateKey { get; set; }
        public ClientCertificateCallbackHandler? ClientCertificateCallbackHandler { get; set; }
        public RemoteCertificateValidationHandler? RemoteCertificateValidationHandler { get; set; }
        public SslSession? PreviousSession { get; set; }
        public IEnumerable<string>? Ciphers { get; set; }

        public static SslOptions _Default { get; }

        static SslOptions()
        {
            _Default = new SslOptions();
        }

        //mandatory constructor
        public SslOptions
        (
            SslStrength sslStrength,
            SslProtocol sslProtocol
        )
        {
            this.SslStrength = sslStrength;
            this.SslProtocol = sslProtocol;
        }

        public SslOptions()
            : this(Ssl._DefaultSslStrength, Ssl._DefaultSslProtocol)
        { }

        public SslOptions
        (
            SslStrength sslStrength,
            SslProtocol sslProtocol,
            X509Store certificateStore,
            X509Certificate certificate,
            PrivateKey privateKey,
            ClientCertificateCallbackHandler clientCertificateCallbackHandler,
            RemoteCertificateValidationHandler remoteCertificateValidationHandler,
            SslSession previousSession,
            IEnumerable<string> ciphers
        )
            : this(sslStrength, sslProtocol)
        {
            this.CertificateStore = certificateStore;
            this.Certificate = certificate;
            this.PrivateKey = privateKey;
            this.ClientCertificateCallbackHandler = clientCertificateCallbackHandler;
            this.RemoteCertificateValidationHandler = remoteCertificateValidationHandler;
            this.PreviousSession = previousSession;
            this.Ciphers = ciphers;
        }

        public SslOptions
        (
            SslStrength sslStrength
        )
            : this(sslStrength, Ssl._DefaultSslProtocol)
        { }

        public SslOptions
        (
            SslProtocol sslProtocol
        )
            : this(Ssl._DefaultSslStrength, sslProtocol)
        { }

        public SslOptions
        (
            SslProtocol sslProtocol,
            IEnumerable<string> allowedCiphers
        )
            : this(Ssl._DefaultSslStrength, sslProtocol)
        {
            this.Ciphers = allowedCiphers;
        }

        public SslOptions
        (
            RemoteCertificateValidationHandler remoteValidation
        )
            : this()
        {
            this.RemoteCertificateValidationHandler = remoteValidation;
        }

        public SslOptions
        (
            X509Store caStore
        )
            : this()
        {
            this.CertificateStore = caStore;
        }

        public SslOptions
        (
            X509Certificate certificate,
            PrivateKey key
        )
            : this()
        {
            this.Certificate = certificate;
            this.PrivateKey = key;
        }

        public SslOptions
        (
            ClientCertificateCallbackHandler clientCertificateCallback
        )
            : this()
        {
            this.ClientCertificateCallbackHandler = clientCertificateCallback;
        }

        public SslOptions
        (
            X509Certificate certificate,
            PrivateKey key,
            X509Store caStore
        )
            : this()
        {
            this.Certificate = certificate;
            this.PrivateKey = key;
            this.CertificateStore = caStore;
        }

        public SslOptions
        (
            X509Certificate certificate,
            PrivateKey key,
            RemoteCertificateValidationHandler remoteCertificateValidationHandler
        )
            : this()
        {
            this.Certificate = certificate;
            this.PrivateKey = key;
            this.RemoteCertificateValidationHandler = remoteCertificateValidationHandler;
        }

        public SslOptions
        (
            X509Certificate certificate,
            PrivateKey key,
            SslStrength sslStrength
        )
            : this (sslStrength, Ssl._DefaultSslProtocol)
        {
            this.Certificate = certificate;
            this.PrivateKey = key;
        }

        public SslOptions
        (
            X509Certificate certificate,
            PrivateKey key,
            SslProtocol sslProtocol
        )
            : this(Ssl._DefaultSslStrength, sslProtocol)
        {
            this.Certificate = certificate;
            this.PrivateKey = key;
        }

        public SslOptions
        (
            X509Certificate certificate,
            PrivateKey key,
            SslProtocol sslProtocol,
            IEnumerable<string> allowedCiphers
        )
            : this(Ssl._DefaultSslStrength, sslProtocol)
        {
            this.Certificate = certificate;
            this.PrivateKey = key;
            this.Ciphers = allowedCiphers;
        }
    }
}
