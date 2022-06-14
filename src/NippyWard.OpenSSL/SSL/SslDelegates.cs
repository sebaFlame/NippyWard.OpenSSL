using System.Collections.Generic;

using NippyWard.OpenSSL.X509;
using NippyWard.OpenSSL.Keys;

namespace NippyWard.OpenSSL.SSL
{
    public delegate bool ClientCertificateCallbackHandler
    (
        IReadOnlyCollection<X509Name> validCA,
        out X509Certificate clientCertificate,
        out PrivateKey clientPrivateKey
    );

    public delegate bool RemoteCertificateValidationHandler
    (
        bool preVerifySucceeded,
        X509Certificate remoteCertificate,
        IReadOnlyCollection<X509Certificate> certificates
    );
}
