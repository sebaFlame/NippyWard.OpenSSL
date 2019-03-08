using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.SSL
{
    internal abstract class SafeSslSessionHandle : BaseReference
    {
        internal SafeSslSessionHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeSslSessionHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected override bool ReleaseHandle()
        {
            this.SSLWrapper.SSL_SESSION_free(this.handle);
            return true;
        }

        internal override void AddRef()
        {
            this.SSLWrapper.SSL_SESSION_up_ref(this);
        }
    }
}
