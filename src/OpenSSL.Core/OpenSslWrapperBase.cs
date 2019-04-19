using System;

using OpenSSL.Core.Interop.Wrappers;
using OpenSSL.Core.Interop;

namespace OpenSSL.Core
{
    public abstract class OpenSslWrapperBase : OpenSslBase, IDisposable
    {
        internal abstract ISafeHandleWrapper HandleWrapper { get; }

        protected OpenSslWrapperBase()
            : base() { }

        ~OpenSslWrapperBase()
        {
            this.Dispose();
        }

        protected abstract void Dispose(bool disposing);

        public void Dispose()
        {
            this.Dispose(false);

            this.HandleWrapper?.Dispose();
        }
    }
}
