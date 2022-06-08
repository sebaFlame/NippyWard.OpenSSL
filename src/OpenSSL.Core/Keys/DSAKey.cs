using System;

using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.Keys
{
    public class DSAKey : PrivateKey
    {
        internal SafeDSAHandle DSAHandle
            => CryptoWrapper.EVP_PKEY_get0_DSA(this._Handle);

        public override KeyType KeyType => KeyType.DSA;

        internal DSAKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        { }

        public DSAKey(int bits, Span<byte> seed)
            : this(GenerateDSAKey(bits, seed))
        { }

        public DSAKey(int bits)
            : this(GenerateDSAKey(bits, Span<byte>.Empty))
        { }

        private static SafeKeyHandle GenerateDSAKey(int bits, Span<byte> seed)
        {
            using (SafeDSAHandle handle = CryptoWrapper.DSA_new())
            {
                CryptoWrapper.DSA_generate_parameters_ex(handle, bits, seed.GetPinnableReference(), seed.Length, out int counter_ret, out ulong h_ret, null);
                CryptoWrapper.DSA_generate_key(handle);

                SafeKeyHandle keyHandle = CryptoWrapper.EVP_PKEY_new();
                CryptoWrapper.EVP_PKEY_set1_DSA(keyHandle, handle);
                return keyHandle;
            }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
}
