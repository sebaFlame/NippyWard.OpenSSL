using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles.Crypto
{
    /// <summary>
    /// Wraps the EVP_MD_CTX object
    /// </summary>
    internal abstract class SafeMessageDigestContextHandle : BaseValue
    {
        public static SafeMessageDigestContextHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeMessageDigestContextHandle>(IntPtr.Zero);

        /// <summary>
        /// Calls EVP_MD_CTX_cleanup() and EVP_MD_CTX_destroy()
        /// </summary>
        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static readonly OPENSSL_sk_freefunc _FreeFunc;

        static SafeMessageDigestContextHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.EVP_MD_CTX_free);
        }

        internal SafeMessageDigestContextHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeMessageDigestContextHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }
    }
}
