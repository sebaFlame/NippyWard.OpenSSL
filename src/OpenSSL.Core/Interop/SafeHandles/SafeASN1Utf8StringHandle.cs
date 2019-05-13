using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles
{
    internal abstract class SafeASN1Utf8StringHandle : SafeAsn1StringHandle
    {
        internal SafeASN1Utf8StringHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeASN1Utf8StringHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected override bool ReleaseHandle()
        {
            this.CryptoWrapper.ASN1_UTF8STRING_free(this.handle);
            return true;
        }

        internal override IntPtr Duplicate()
        {
            return this.CryptoWrapper.ASN1_STRING_dup(this);
        }
    }
}
