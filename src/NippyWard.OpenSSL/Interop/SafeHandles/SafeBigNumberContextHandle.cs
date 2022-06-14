using System;
using System.Collections.Generic;
using System.Text;
using NippyWard.OpenSSL.Interop.Wrappers;

namespace NippyWard.OpenSSL.Interop.SafeHandles
{
    internal abstract class SafeBigNumberContextHandle : BaseValue
    {
        public static SafeBigNumberContextHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeBigNumberContextHandle>(IntPtr.Zero);

        /// <summary>
        /// Calls BN_CTX_free()
        /// </summary>
        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static readonly OPENSSL_sk_freefunc _FreeFunc;

        static SafeBigNumberContextHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.BN_CTX_free);
        }

        /// <summary>
        /// Calls BN_CTX_new()
        /// </summary>
        internal SafeBigNumberContextHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeBigNumberContextHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        /// <summary>
        /// Returns BN_CTX_get()
        /// </summary>
        public SafeBigNumberHandle Get
        {
            get { return Native.CryptoWrapper.BN_CTX_get(this); }
        }

        /// <summary>
        /// Calls BN_CTX_start()
        /// </summary>
        public void Start()
        {
            Native.CryptoWrapper.BN_CTX_start(this);
        }

        /// <summary>
        /// Calls BN_CTX_end()
        /// </summary>
        public void End()
        {
            Native.CryptoWrapper.BN_CTX_end(this);
        }
    }
}
