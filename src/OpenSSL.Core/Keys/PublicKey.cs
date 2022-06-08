using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.Crypto;

namespace OpenSSL.Core.Keys
{
    public class PublicKey : Key, IPublicKey
    {
        public override KeyType KeyType => (KeyType)CryptoWrapper.EVP_PKEY_base_id(this._Handle);

        internal PublicKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        { }
    }
}
