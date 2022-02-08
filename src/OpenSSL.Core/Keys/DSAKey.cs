using System;

using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.Keys
{
    public class DSAKey : PrivateKey
    {
        private SafeDSAHandle dsaHandle;

        public override KeyType KeyType => KeyType.DSA;

        internal DSAKey(KeyInternal handleWrapper)
            : base(handleWrapper) { }

        internal DSAKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        {
            this.dsaHandle = CryptoWrapper.EVP_PKEY_get0_DSA(this.KeyWrapper.Handle);
        }

        public DSAKey(int bits, Span<byte> seed)
            : base()
        {
            this.generateDSA(bits, seed);
        }

        public DSAKey(int bits)
            : base()
        {
            byte[] buffer = Array.Empty<byte>();
            this.generateDSA(bits, new Span<byte>(buffer));
        }

        private void generateDSA(int bits, Span<byte> seed)
        {
            this.dsaHandle = CryptoWrapper.DSA_new();
            CryptoWrapper.DSA_generate_parameters_ex(this.dsaHandle, bits, seed.GetPinnableReference(), seed.Length, out int counter_ret, out ulong h_ret, null);
            CryptoWrapper.DSA_generate_key(this.dsaHandle);
        }

        internal override KeyInternal GenerateKeyInternal()
        {
            if (this.dsaHandle is null || this.dsaHandle.IsInvalid)
                throw new InvalidOperationException("RSA key has not been created yet");

            SafeKeyHandle keyHandle = CryptoWrapper.EVP_PKEY_new();
            CryptoWrapper.EVP_PKEY_set1_DSA(keyHandle, this.dsaHandle);
            return new KeyInternal(keyHandle);
        }

        protected override void Dispose(bool disposing)
        {
            if (!(this.dsaHandle is null) && !this.dsaHandle.IsInvalid)
                this.dsaHandle.Dispose();

            base.Dispose(disposing);
        }
    }
}
