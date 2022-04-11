using System;
using OpenSSL.Core.Interop.Wrappers;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.Crypto
{
    internal abstract class SafeKeyContextHandle : BaseValue
    {
        public static SafeKeyContextHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeKeyContextHandle>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static OPENSSL_sk_freefunc _FreeFunc;

        static SafeKeyContextHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.EVP_PKEY_CTX_free);
        }

        internal SafeKeyContextHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeKeyContextHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }
    }
}
