using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.Crypto
{
    internal abstract class SafeEngineHandle : BaseReference
    {
        internal SafeEngineHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeEngineHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected override bool ReleaseHandle()
        {
            this.CryptoWrapper.ENGINE_free(this.handle);
            return true;
        }

        internal override void AddRef()
        {
            this.CryptoWrapper.ENGINE_up_ref(this);
        }
    }
}
