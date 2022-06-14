using System;
using System.Collections.Generic;
using System.Text;

namespace NippyWard.OpenSSL
{
    /// <summary>
    /// Set of types that this CryptoKey can be.
    /// </summary>
    public enum KeyType
    {
        /// <summary>
        /// EVP_PKEY_RSA
        /// </summary>
        RSA = 6,
        /// <summary>
        /// EVP_PKEY_DSA
        /// </summary>
        DSA = 116,
        /// <summary>
        /// EVP_PKEY_DH
        /// </summary>
        DH = 28,
        /// <summary>
        /// EVP_PKEY_EC
        /// </summary>
        EC = 408
    }
}
