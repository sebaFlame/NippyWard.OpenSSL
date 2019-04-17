using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;

namespace OpenSSL.Core.SSL
{
    public delegate bool ClientCertificateCallbackHandler(
        X509Name[] validCA,
        out X509Certificate clientCertificate,
        out PrivateKey clientPrivateKey
    );

    public delegate bool RemoteCertificateValidationHandler(
        VerifyResult preVerify,
        X509Certificate remoteCertificate,
        X509CertificateList certificates
    );
}
