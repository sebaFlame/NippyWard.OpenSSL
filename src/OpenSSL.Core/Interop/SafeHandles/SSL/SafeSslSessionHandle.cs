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

        internal SafeSslSessionHandle(IntPtr ptr, bool takeOwnership, bool isNew)
            : base(ptr, takeOwnership, isNew)
        { }

        protected override bool ReleaseHandle()
        {
            SSLWrapper.SSL_SESSION_free(this.handle);
            return true;
        }

        internal override void AddRef()
        {
            SSLWrapper.SSL_SESSION_up_ref(this);
        }
    }
}
