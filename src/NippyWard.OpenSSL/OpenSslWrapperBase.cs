using System;
using System.Runtime.InteropServices;

namespace NippyWard.OpenSSL
{
    public abstract class OpenSslWrapperBase
        : OpenSslBase,
            ISafeHandleWrapper,
            IDisposable
    {
        public abstract SafeHandle Handle { get; }

        protected OpenSslWrapperBase()
            : base() { }

        ~OpenSslWrapperBase()
        {
            this.DisposeInternal(false);
        }

        protected abstract void Dispose(bool disposing);

        private void DisposeInternal(bool isDisposing)
        {
            this.Dispose(isDisposing);

            if (this.Handle.IsClosed
                || this.Handle.IsInvalid)
            {
                return;
            }

            this.Handle.Dispose();
        }

        public void Dispose()
        {
            this.DisposeInternal(true);

            GC.SuppressFinalize(this);
        }
    }
}
