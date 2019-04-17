using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
    /// <summary>
    /// Wraps the X509_STORE object
    /// </summary>
    internal abstract class SafeX509ObjectHandle : BaseReference, IStackable
    {
        internal SafeX509ObjectHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeX509ObjectHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected override bool ReleaseHandle()
        {
            this.CryptoWrapper.X509_OBJECT_free(this.handle);
            return true;
        }

        internal override void AddRef()
        {
            this.CryptoWrapper.X509_OBJECT_up_ref_count(this);
        }
    }
}
