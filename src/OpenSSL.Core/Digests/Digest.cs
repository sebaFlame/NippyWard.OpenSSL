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
        private bool finalized;

        public Digest(DigestType digestType)
            : base(digestType)
        {
            this.CryptoWrapper.EVP_DigestInit(this.digestCtxHandle, this.DigestWrapper.Handle);
        }

        public void Update(Span<byte> buffer)
        {
            if (this.finalized)
                throw new InvalidOperationException("Digest has already been finalized");

            this.CryptoWrapper.EVP_DigestUpdate(this.digestCtxHandle, buffer.GetPinnableReference(), (uint)buffer.Length);
        }

        public void Finalize(out Span<byte> digest)
        {
            if (this.finalized)
                throw new InvalidOperationException("Digest has already been finalized");

            byte[] digestBuf = new byte[Native.EVP_MAX_MD_SIZE];
            Span<byte> digestSpan = new Span<byte>(digestBuf);

            this.CryptoWrapper.EVP_DigestFinal(this.digestCtxHandle, ref digestSpan.GetPinnableReference(), out uint length);
            digest = digestSpan.Slice(0, (int)length);
        }
    }
}
