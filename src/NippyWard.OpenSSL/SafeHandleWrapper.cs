using System;
using System.Runtime.InteropServices;

using NippyWard.OpenSSL.Interop.SafeHandles;

namespace NippyWard.OpenSSL
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
            this.Handle.Dispose();
        }
    }
}
