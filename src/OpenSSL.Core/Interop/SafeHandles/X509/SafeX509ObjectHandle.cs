using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
    /// <summary>
    /// Wraps the X509_OBJECT object. Can contain a X509, X509_CRL or EVP_PKEY
    /// </summary>
    internal abstract class SafeX509ObjectHandle : BaseValue, IStackable
    {
        internal SafeX509ObjectHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeX509ObjectHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected override bool ReleaseHandle()
        {
            CryptoWrapper.X509_OBJECT_free(this.handle);
            return true;
        }
    }
}
