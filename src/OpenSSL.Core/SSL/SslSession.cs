using System;
using System.Runtime.InteropServices;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.SSL;

namespace OpenSSL.Core.SSL
{
    public class SslSession
        : OpenSslWrapperBase,
            ISafeHandleWrapper<SafeSslSessionHandle>
    {
        SafeSslSessionHandle ISafeHandleWrapper<SafeSslSessionHandle>.Handle
            => this._Handle;
        public override SafeHandle Handle
            => this._Handle;

        internal readonly SafeSslSessionHandle _Handle;

        internal SslSession(SafeSslSessionHandle sessionHandle)
        {
            this._Handle = Native.SafeHandleFactory.CreateTakeOwnershipSafeHandle<SafeSslSessionHandle>(sessionHandle.DangerousGetHandle());
        }

        protected override void Dispose(bool isDisposing)
        {
            //NOP
        }
    }
}
