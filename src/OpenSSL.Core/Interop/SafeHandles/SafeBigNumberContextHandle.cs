using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles
{
    internal abstract class SafeBigNumberContextHandle : BaseValue
    {
        /// <summary>
        /// Calls BN_CTX_new()
        /// </summary>
        internal SafeBigNumberContextHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
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

        /// <summary>
        /// Calls BN_CTX_free()
        /// </summary>
        protected override bool ReleaseHandle()
        {
            this.CryptoWrapper.BN_CTX_free(this.handle);
            return true;
        }

        internal override IntPtr Duplicate()
        {
            throw new NotImplementedException();
        }
    }
}
