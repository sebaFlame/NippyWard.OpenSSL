using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.SSL
{
    public enum SslStrength
    {
        /// <summary>
        /// Everything is permitted. This retains compatibility with previous versions of OpenSSL.
        /// </summary>
        Level0,
        /// <summary>
        /// The security level corresponds to a minimum of 80 bits of security. 
        /// Any parameters offering below 80 bits of security are excluded. 
        /// As a result RSA, DSA and DH keys shorter than 1024 bits and ECC keys shorter than 160 bits are prohibited. 
        /// All export ciphersuites are prohibited since they all offer less than 80 bits of security. 
        /// SSL version 2 is prohibited. Any ciphersuite using MD5 for the MAC is also prohibited.
        /// </summary>
        Level1,
        /// <summary>
        /// Security level set to 112 bits of security. 
        /// As a result RSA, DSA and DH keys shorter than 2048 bits and ECC keys shorter than 224 bits are prohibited. 
        /// In addition to the level 1 exclusions any ciphersuite using RC4 is also prohibited. 
        /// SSL version 3 is also not allowed. Compression is disabled.
        /// </summary>
        Level2,
        /// <summary>
        /// Security level set to 128 bits of security. 
        /// As a result RSA, DSA and DH keys shorter than 3072 bits and ECC keys shorter than 256 bits are prohibited. 
        /// In addition to the level 2 exclusions ciphersuites not offering forward secrecy are prohibited. 
        /// TLS versions below 1.1 are not permitted. Session tickets are disabled.
        /// </summary>
        Level3,
        /// <summary>
        /// Security level set to 192 bits of security. As a result RSA, DSA and DH keys shorter than 7680 bits and ECC keys shorter than 384 bits are prohibited. 
        /// Ciphersuites using SHA1 for the MAC are prohibited. TLS versions below 1.2 are not permitted.
        /// </summary>
        Level4,
        /// <summary>
        /// Security level set to 256 bits of security. As a result RSA, DSA and DH keys shorter than 15360 bits and ECC keys shorter than 512 bits are prohibited.
        /// </summary>
        Level5
    }


}
