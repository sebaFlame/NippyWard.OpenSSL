using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.Crypto;

namespace OpenSSL.Core.Keys
{
    public class PublicKey : Key, IPublicKey
    {
        public override KeyType KeyType => (KeyType)CryptoWrapper.EVP_PKEY_base_id(this.KeyWrapper.Handle);

        internal PublicKey(KeyInternal handleWrapper)
            : base(handleWrapper) { }

        internal PublicKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        { }

        internal override KeyInternal GenerateKeyInternal()
        {
            throw new InvalidOperationException("A public key can not be generated.");
        }
    }
}
