using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.SSL
{
    internal abstract class SafeSslSessionHandle : BaseReference
    {
        internal SafeSslSessionHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeSslSessionHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected override bool ReleaseHandle()
        {
            SSLWrapper.SSL_SESSION_free(this.handle);
            return true;
        }

        internal override void AddReference()
        {
            SSLWrapper.SSL_SESSION_up_ref(this);
        }
    }
}
