using System;
using System.Collections.Generic;
using System.Text;

using NippyWard.OpenSSL.Interop.SafeHandles;
using NippyWard.OpenSSL.Interop.SafeHandles.Crypto;

namespace NippyWard.OpenSSL.Keys
{
    public class PublicKey : Key, IPublicKey
    {
        public override KeyType KeyType => (KeyType)CryptoWrapper.EVP_PKEY_get_base_id(this._Handle);

        internal PublicKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        { }
    }
}
