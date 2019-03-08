using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop.Wrappers;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;

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
