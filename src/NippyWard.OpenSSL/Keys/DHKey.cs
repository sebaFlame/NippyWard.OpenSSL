using System;
using System.Collections.Generic;
using System.Text;
using NippyWard.OpenSSL.Interop.SafeHandles.Crypto;

namespace NippyWard.OpenSSL.Keys
{
    public class DHKey : PrivateKey
    {
        internal SafeDHHandle DHhHandle
            => CryptoWrapper.EVP_PKEY_get0_DH(this._Handle);

        public override KeyType KeyType => KeyType.DH;

        internal DHKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        { }

        public DHKey(int primeLength, ushort generator)
            : this(GenerateDHKey(primeLength, generator))
        { }

        private static SafeKeyHandle GenerateDHKey(int primeLength, ushort generator)
        {
            using (SafeDHHandle handle = CryptoWrapper.DH_new())
            {
                CryptoWrapper.DH_generate_parameters_ex(handle, primeLength, generator, null);
                CryptoWrapper.DH_generate_key(handle);

                SafeKeyHandle keyHandle = CryptoWrapper.EVP_PKEY_new();
                CryptoWrapper.EVP_PKEY_set1_DH(keyHandle, handle);
                return keyHandle;
            }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
}
