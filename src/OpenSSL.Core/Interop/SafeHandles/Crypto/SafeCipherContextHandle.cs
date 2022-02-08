using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.Crypto
{
    /// <summary>
    /// Wraps the EVP_CIPHER_CTX object.
    /// </summary>
    internal abstract class SafeCipherContextHandle : BaseValue
    {
        /// <summary>
        /// Calls OPENSSL_malloc() and initializes the buffer using EVP_CIPHER_CTX_init()
        /// </summary>
        /// <param name="cipher"></param>
        internal SafeCipherContextHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeCipherContextHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        #region IDisposable Members

        protected override bool ReleaseHandle()
        {
            CryptoWrapper.EVP_CIPHER_CTX_free(this.handle);
            return true;
        }
        #endregion
    }
}
