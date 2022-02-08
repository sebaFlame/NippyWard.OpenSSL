using System;

using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.Keys
{
    public class RSAKey : PrivateKey, IPublicKey
    {
        private SafeRSAHandle rsaHandle;

        public override KeyType KeyType => KeyType.RSA;

        internal RSAKey(KeyInternal handleWrapper)
            : base(handleWrapper) { }

        internal RSAKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        {
            this.rsaHandle = CryptoWrapper.EVP_PKEY_get0_RSA(this.KeyWrapper.Handle);
        }

        public RSAKey(int bits)
            : base()
        {
            this.rsaHandle = CryptoWrapper.RSA_new();

            using (SafeBigNumberHandle bn = CryptoWrapper.BN_new())
            {
                CryptoWrapper.BN_rand(bn, 24, 65537, 1);
                CryptoWrapper.BN_set_bit(bn, 0); //TODO: check if uneven
                CryptoWrapper.RSA_generate_key_ex(this.rsaHandle, bits, bn, null);
            }
        }

        internal override KeyInternal GenerateKeyInternal()
        {
            if(this.rsaHandle is null || this.rsaHandle.IsInvalid)
                throw new InvalidOperationException("RSA key has not been created yet");

            CryptoWrapper.RSA_check_key(this.rsaHandle);

            SafeKeyHandle keyHandle = CryptoWrapper.EVP_PKEY_new();
            CryptoWrapper.EVP_PKEY_set1_RSA(keyHandle, this.rsaHandle);
            return new KeyInternal(keyHandle);
        }

        protected override void Dispose(bool disposing)
        {
            if (!(this.rsaHandle is null) && !this.rsaHandle.IsInvalid)
                this.rsaHandle.Dispose();

            base.Dispose(disposing);
        }
    }
}
