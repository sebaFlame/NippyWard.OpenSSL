using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles
{
    internal abstract class SafeASN1Utf8StringHandle : SafeAsn1StringHandle
    {
        public static new SafeASN1Utf8StringHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeASN1Utf8StringHandle>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static readonly OPENSSL_sk_freefunc _FreeFunc;

        static SafeASN1Utf8StringHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.ASN1_UTF8STRING_free);
        }

        internal SafeASN1Utf8StringHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeASN1Utf8StringHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }
    }
}
