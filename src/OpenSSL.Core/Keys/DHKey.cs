using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL.Core.Interop.SafeHandles.Crypto;

namespace OpenSSL.Core.Keys
{
    public class DHKey : PrivateKey
    {
        private SafeDHHandle dhHandle;

        public override KeyType KeyType => KeyType.DH;

        internal DHKey(KeyInternal handleWrapper)
            : base(handleWrapper) { }

        internal DHKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        {
            this.dhHandle = CryptoWrapper.EVP_PKEY_get0_DH(this.KeyWrapper.Handle);
        }

        public DHKey(int primeLength, ushort generator)
            : base()
        {
            if (generator <= 1)
                throw new InvalidOperationException("Invalid generator");

            this.dhHandle = CryptoWrapper.DH_new();
            CryptoWrapper.DH_generate_parameters_ex(this.dhHandle, primeLength, generator, null);
            CryptoWrapper.DH_generate_key(this.dhHandle);
        }

        internal override KeyInternal GenerateKeyInternal()
        {
            if (this.dhHandle is null || this.dhHandle.IsInvalid)
                throw new InvalidOperationException("RSA key has not been created yet");

            SafeKeyHandle keyHandle = CryptoWrapper.EVP_PKEY_new();
            CryptoWrapper.EVP_PKEY_set1_DH(keyHandle, this.dhHandle);
            return new KeyInternal(keyHandle);
        }

        protected override void Dispose(bool disposing)
        {
            if (!(this.dhHandle is null) && !this.dhHandle.IsInvalid)
                this.dhHandle.Dispose();

            base.Dispose(disposing);
        }
    }
}
