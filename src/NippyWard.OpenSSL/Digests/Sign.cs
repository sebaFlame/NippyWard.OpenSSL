using System;
using System.Collections.Generic;
using System.Text;

using NippyWard.OpenSSL.ASN1;
using NippyWard.OpenSSL.Keys;
using NippyWard.OpenSSL.Interop.SafeHandles.Crypto;

namespace NippyWard.OpenSSL.Digests
{
    public class Sign : DigestBase
    {
        public Sign(DigestType digestType)
            : base(digestType)
        {
            CryptoWrapper.EVP_SignInit(this.DigestCtxHandle, this._Handle);
        }

        public void Update(Span<byte> buffer)
        {
            CryptoWrapper.EVP_SignUpdate(this.DigestCtxHandle, buffer.GetPinnableReference(), (uint)buffer.Length);
        }

        public void Finalize(Key key, out Span<byte> signature)
        {
            byte[] signBuf = new byte[CryptoWrapper.EVP_PKEY_size(key._Handle)];
            Span<byte> signSpan = new Span<byte>(signBuf);

            CryptoWrapper.EVP_SignFinal(this.DigestCtxHandle, ref signSpan.GetPinnableReference(), out uint length, key._Handle);
            signature = signSpan.Slice(0, (int)length);
        }
    }
}
