using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Keys;
using OpenSSL.Core.Interop.SafeHandles.Crypto;

namespace OpenSSL.Core.Digests
{
    public class Sign : DigestBase
    {
        private bool finalized;

        public Sign(DigestType digestType)
            : base(digestType)
        {
            this.CryptoWrapper.EVP_SignInit(this.digestCtxHandle, this.DigestWrapper.Handle);
        }

        public void Update(Span<byte> buffer)
        {
            if (this.finalized)
                throw new InvalidOperationException("Sign has already been finalized");

            this.CryptoWrapper.EVP_SignUpdate(this.digestCtxHandle, buffer.GetPinnableReference(), (uint)buffer.Length);
        }

        public void Finalize(Key key, out Span<byte> signature)
        {
            if (this.finalized)
                throw new InvalidOperationException("Sign has already been finalized");

            byte[] signBuf = new byte[this.CryptoWrapper.EVP_PKEY_size(key.KeyWrapper.Handle)];
            Span<byte> signSpan = new Span<byte>(signBuf);

            this.CryptoWrapper.EVP_SignFinal(this.digestCtxHandle, ref signSpan.GetPinnableReference(), out uint length, key.KeyWrapper.Handle);
            signature = signSpan.Slice(0, (int)length);
        }
    }
}
