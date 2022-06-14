using System;

using NippyWard.OpenSSL.Interop.SafeHandles.Crypto;
using NippyWard.OpenSSL.Interop.SafeHandles;

namespace NippyWard.OpenSSL.Keys
{
    public class RSAKey : PrivateKey, IPublicKey
    {
        internal SafeRSAHandle RSAHandle
            => CryptoWrapper.EVP_PKEY_get0_RSA(this._Handle);

        public override KeyType KeyType => KeyType.RSA;

        internal RSAKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        { }

        public RSAKey(int bits)
            : base(GenerateRSAKey(bits))
        { }

        private static SafeKeyHandle GenerateRSAKey(int bits)
        {
            using (SafeRSAHandle handle = CryptoWrapper.RSA_new())
            {
                SafeBigNumberHandle bn = CryptoWrapper.BN_new();
                //using (SafeBigNumberHandle bn = CryptoWrapper.BN_new())
                //{
                    CryptoWrapper.BN_rand(bn, 24, 65537, 1);
                    CryptoWrapper.BN_set_bit(bn, 0);
                    CryptoWrapper.RSA_generate_key_ex(handle, bits, bn, null);
                //}

                SafeKeyHandle keyHandle = CryptoWrapper.EVP_PKEY_new();
                CryptoWrapper.EVP_PKEY_set1_RSA(keyHandle, handle);
                return keyHandle;
            }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
}
