using System;

using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.X509;

namespace OpenSSL.Core.SSL
{
    internal delegate int ClientCertCallbackHandler(
        SafeSslHandle ssl,
        out SafeX509CertificateHandle cert,
        out SafeKeyHandle key
    );

    /// <summary>
    ///
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="cert"></param>
    /// <param name="chain"></param>
    /// <param name="depth"></param>
    /// <param name="result"></param>
    /// <returns></returns>
    internal delegate bool RemoteCertificateValidationHandler(
        object sender,
        X509Certificate cert,
        SafeStackHandle<SafeX509CertificateHandle> chain,
        int depth,
        VerifyResult result
    );

    /// <summary>
    ///
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="targetHost"></param>
    /// <param name="localCerts"></param>
    /// <param name="remoteCert"></param>
    /// <param name="acceptableIssuers"></param>
    /// <returns></returns>
    internal delegate X509Certificate LocalCertificateSelectionHandler(
        object sender,
        string targetHost,
        SafeStackHandle<SafeX509CertificateHandle> localCerts,
        X509Certificate remoteCert,
        string[] acceptableIssuers
    );
}
