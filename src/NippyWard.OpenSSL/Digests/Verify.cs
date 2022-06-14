using System;
using System.Collections.Generic;
using System.Text;

using NippyWard.OpenSSL.ASN1;
using NippyWard.OpenSSL.Keys;
using NippyWard.OpenSSL.Interop.SafeHandles.Crypto;

namespace NippyWard.OpenSSL.Digests
{
    public class Verify : DigestBase
    {
        public Verify(DigestType digestType)
            : base(digestType)
        {
            CryptoWrapper.EVP_VerifyInit_ex(this.DigestCtxHandle, this._Handle, SafeEngineHandle.Zero);
        }

        public void Update(Span<byte> buffer)
        {
            CryptoWrapper.EVP_VerifyUpdate(this.DigestCtxHandle, buffer.GetPinnableReference(), (uint)buffer.Length);
        }

        public bool Finalize(Key key, Span<byte> signature)
        {
            return CryptoWrapper.EVP_VerifyFinal(this.DigestCtxHandle, signature.GetPinnableReference(), (uint)signature.Length, key._Handle) > 0;
        }
    }
}
