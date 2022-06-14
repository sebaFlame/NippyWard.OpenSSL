using System;
using NippyWard.OpenSSL.Interop.Wrappers;

namespace NippyWard.OpenSSL.Interop.SafeHandles.Crypto
{
    /// <summary>
    /// Wraps the EVP_CIPHER_CTX object.
    /// </summary>
    internal abstract class SafeCipherContextHandle : BaseValue
    {
        public static SafeCipherContextHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeCipherContextHandle>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static readonly OPENSSL_sk_freefunc _FreeFunc;

        static SafeCipherContextHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.EVP_CIPHER_CTX_free);
        }

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
    }
}
