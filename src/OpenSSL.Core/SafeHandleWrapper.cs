using System;
using System.Runtime.InteropServices;

using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core
{
    internal abstract class SafeHandleWrapper<T> : OpenSslBase, ISafeHandleWrapper
        where T : SafeBaseHandle
    {
        internal T Handle { get; private set; }
        SafeHandle ISafeHandleWrapper.Handle => this.Handle;

        internal SafeHandleWrapper(T safeHandle)
            : base()
        {
            this.Handle = safeHandle;
        }

        public void Dispose()
        {
            if (!(this.Handle is null) && !this.Handle.IsInvalid)
                this.Handle.Dispose();
        }
    }
}
