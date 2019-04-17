using System;

using OpenSSL.Core.Interop.Wrappers;
using OpenSSL.Core.Interop;

namespace OpenSSL.Core
{
    public abstract class Base : IDisposable
    {
        internal ILibCryptoWrapper CryptoWrapper { get; private set; }
        internal ILibSSLWrapper SSLWrapper { get; private set; }

        protected Base()
        {
            this.CryptoWrapper = Native.CryptoWrapper;
            this.SSLWrapper = Native.SSLWrapper;
        }

        public abstract void Dispose();
    }
}
