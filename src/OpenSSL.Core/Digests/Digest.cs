using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop;

namespace OpenSSL.Core.Digests
{
    public class Digest : DigestBase
    {
        public Digest(DigestType digestType)
            : base(digestType)
        {
            CryptoWrapper.EVP_DigestInit(this.DigestCtxHandle, this._Handle);
        }

        public void Update(Span<byte> buffer)
        {
            CryptoWrapper.EVP_DigestUpdate(this.DigestCtxHandle, buffer.GetPinnableReference(), (uint)buffer.Length);
        }

        public void Finalize(out Span<byte> digest)
        {
            byte[] digestBuf = new byte[Native.EVP_MAX_MD_SIZE];
            Span<byte> digestSpan = new Span<byte>(digestBuf);

            CryptoWrapper.EVP_DigestFinal(this.DigestCtxHandle, ref digestSpan.GetPinnableReference(), out uint length);
            digest = digestSpan.Slice(0, (int)length);
        }
    }
}
