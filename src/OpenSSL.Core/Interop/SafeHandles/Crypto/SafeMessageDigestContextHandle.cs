using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.Crypto
{
    /// <summary>
    /// Wraps the EVP_MD_CTX object
    /// </summary>
    internal abstract class SafeMessageDigestContextHandle : BaseValue
    {
        internal SafeMessageDigestContextHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeMessageDigestContextHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        #region IDisposable Members

        /// <summary>
        /// Calls EVP_MD_CTX_cleanup() and EVP_MD_CTX_destroy()
        /// </summary>
        protected override bool ReleaseHandle()
        {
            CryptoWrapper.EVP_MD_CTX_free(this.handle);
            return true;
        }
        #endregion
    }
}
