using System;

using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.Collections
{
    internal class OpenSslReadOnlyWrapper<TOuter, TWrapper, THandle> : OpenSslEnumerableWrapper<TOuter, TWrapper, THandle>, IOpenSslIReadOnlyCollection<TOuter>
        where THandle : SafeBaseHandle, IStackable
        where TWrapper : SafeHandleWrapper<THandle>
        where TOuter : OpenSslWrapperBase
    {
        public int Count => this.Handle.Count;

        internal OpenSslReadOnlyWrapper(SafeStackHandle<THandle> safeHandle)
            : base(safeHandle)
        { }

        internal OpenSslReadOnlyWrapper()
            : base()
        { }
    }
}
