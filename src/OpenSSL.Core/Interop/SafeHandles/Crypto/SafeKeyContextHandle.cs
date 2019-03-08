using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.Crypto
{
    internal abstract class SafeKeyContextHandle : BaseValue
    {
        internal SafeKeyContextHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeKeyContextHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected override bool ReleaseHandle()
        {
            this.CryptoWrapper.EVP_PKEY_CTX_free(this.handle);
            return true;
        }

        internal override IntPtr Duplicate()
        {
            return this.CryptoWrapper.EVP_PKEY_CTX_dup(this);
        }
    }
}
