using System;
using OpenSSL.Core.Interop.Wrappers;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.Crypto
{
    internal abstract class SafeEngineHandle : BaseReference
    {
        public static SafeEngineHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeEngineHandle>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static OPENSSL_sk_freefunc _FreeFunc;

        static SafeEngineHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.ENGINE_free);
        }

        internal SafeEngineHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeEngineHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        internal override void AddReference()
        {
            CryptoWrapper.ENGINE_up_ref(this);
        }
    }
}
