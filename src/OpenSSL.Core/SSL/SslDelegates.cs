using System.Collections.Generic;

using OpenSSL.Core.X509;
using OpenSSL.Core.Keys;

namespace OpenSSL.Core.SSL
{
    public delegate bool ClientCertificateCallbackHandler(
        IReadOnlyCollection<X509Name> validCA,
        out X509Certificate clientCertificate,
        out PrivateKey clientPrivateKey
    );

    public delegate bool RemoteCertificateValidationHandler(
        bool preVerifySucceeded,
        X509Certificate remoteCertificate,
        IReadOnlyCollection<X509Certificate> certificates
    );
}
