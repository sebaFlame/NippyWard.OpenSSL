using System;
using System.Collections.Generic;
using System.Text;
using NippyWard.OpenSSL.Interop.Wrappers;

namespace NippyWard.OpenSSL.Interop.SafeHandles.X509
{
    /// <summary>
    /// Wraps the X509_OBJECT object. Can contain a X509, X509_CRL or EVP_PKEY
    /// </summary>
    internal abstract class SafeX509ObjectHandle : BaseValue, IStackable
    {
        public static SafeX509ObjectHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeX509ObjectHandle>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static readonly OPENSSL_sk_freefunc _FreeFunc;

        static SafeX509ObjectHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.X509_OBJECT_free);
        }

        internal SafeX509ObjectHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeX509ObjectHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }
    }
}
