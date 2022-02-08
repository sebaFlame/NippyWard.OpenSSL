using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.Crypto
{
    internal abstract class SafeEngineHandle : BaseReference
    {
        internal SafeEngineHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeEngineHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected override bool ReleaseHandle()
        {
            CryptoWrapper.ENGINE_free(this.handle);
            return true;
        }

        internal override void AddReference()
        {
            CryptoWrapper.ENGINE_up_ref(this);
        }
    }
}
