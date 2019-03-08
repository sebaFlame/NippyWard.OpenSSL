using System;

using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.Keys
{
    public class RSAKey : PrivateKey, IPublicKey
    {
        private SafeRSAHandle rsaHandle;

        public override KeyType KeyType => KeyType.RSA;

        internal RSAKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        {
            this.rsaHandle = this.CryptoWrapper.EVP_PKEY_get1_RSA(this.KeyHandle);
        }

        public RSAKey(int bits)
            : base()
        {
            this.rsaHandle = this.CryptoWrapper.RSA_new();

            SafeBigNumberHandle bn;
            using (bn = this.CryptoWrapper.BN_new())
            {
                this.CryptoWrapper.BN_rand(bn, 24, 65537, 1);
                this.CryptoWrapper.BN_set_bit(bn, 0); //TODO: check if uneven
                this.CryptoWrapper.RSA_generate_key_ex(this.rsaHandle, bits, bn, null);
            }
        }

        internal override SafeKeyHandle GenerateKeyInternal()
        {
            if(this.rsaHandle is null || this.rsaHandle.IsInvalid)
                throw new InvalidOperationException("RSA key has not been created yet");

            this.CryptoWrapper.RSA_check_key(this.rsaHandle);

            SafeKeyHandle keyHandle = this.CryptoWrapper.EVP_PKEY_new();
            this.CryptoWrapper.EVP_PKEY_set1_RSA(keyHandle, this.rsaHandle);
            return keyHandle;
        }

        public override void Dispose()
        {
            if (!(this.rsaHandle is null) && !this.rsaHandle.IsInvalid)
                this.rsaHandle.Dispose();

            base.Dispose();
        }
    }
}
