using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Collections
{
    public abstract class OpenSslEnumerable<T> : IEnumerable<T>, IDisposable
        where T : OpenSslWrapperBase
    {
        internal abstract IOpenSslIEnumerable<T> InternalEnumerable { get; }

        protected OpenSslEnumerable() { }

        public IEnumerator<T> GetEnumerator()
        {
            return this.InternalEnumerable.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.InternalEnumerable.GetEnumerator();
        }

        public void Dispose()
        {
            this.InternalEnumerable?.Dispose();
        }
    }
}
