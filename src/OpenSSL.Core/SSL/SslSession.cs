using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.SSL;

namespace OpenSSL.Core.SSL
{
    public class SslSession : OpenSslWrapperBase
    {
        internal class SslSesionInternal : SafeHandleWrapper<SafeSslSessionHandle>
        {
            internal SslSesionInternal(SafeSslSessionHandle safeHandle)
                : base(safeHandle) 
            {
                //only add the reference after the creation was successful
                safeHandle.AddReference();
            }
        }

        internal SslSesionInternal SessionWrapper { get; private set; }
        internal override ISafeHandleWrapper HandleWrapper => this.SessionWrapper;

        internal SslSession(SafeSslSessionHandle sessionHandle)
        {
            this.SessionWrapper = new SslSesionInternal
            (
                Native.SafeHandleFactory.CreateTakeOwnershipSafeHandle<SafeSslSessionHandle>(sessionHandle.DangerousGetHandle())
            );
        }

        protected override void Dispose(bool isDisposing)
        {
            //NOP
        }
    }
}
