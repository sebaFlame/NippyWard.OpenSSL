﻿using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Keys;

namespace OpenSSL.Core.Digests
{
    public class Verify : DigestBase
    {
        private bool finalized;

        internal Verify(DigestInternal handleWarpper)
            : base(handleWarpper) { }

        public Verify(DigestType digestType)
            : base(digestType)
        {
            CryptoWrapper.EVP_VerifyInit_ex(this.digestCtxHandle, this.DigestWrapper.Handle, null);
        }

        public void Update(Span<byte> buffer)
        {
            if (this.finalized)
                throw new InvalidOperationException("Sign has already been finalized");

            CryptoWrapper.EVP_VerifyUpdate(this.digestCtxHandle, buffer.GetPinnableReference(), (uint)buffer.Length);
        }

        public bool Finalize(Key key, Span<byte> signature)
        {
            if (this.finalized)
                throw new InvalidOperationException("Sign has already been finalized");

            return CryptoWrapper.EVP_VerifyFinal(this.digestCtxHandle, signature.GetPinnableReference(), (uint)signature.Length, key.KeyWrapper.Handle) > 0;
        }
    }
}
