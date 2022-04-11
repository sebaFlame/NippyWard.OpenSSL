using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles.SSL
{
    internal abstract class SafeSslSessionHandle : BaseReference
    {
        public static SafeSslSessionHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeSslSessionHandle>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static OPENSSL_sk_freefunc _FreeFunc;

        static SafeSslSessionHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(SSLWrapper.SSL_SESSION_free);
        }

        internal SafeSslSessionHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeSslSessionHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        internal override void AddReference()
        {
            SSLWrapper.SSL_SESSION_up_ref(this);
        }
    }
}
