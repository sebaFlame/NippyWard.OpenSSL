using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core
{
    public abstract class OpenSslBase
    {
        internal ILibCryptoWrapper CryptoWrapper { get; private set; }
        internal ILibSSLWrapper SSLWrapper { get; private set; }

        protected OpenSslBase()
        {
            this.CryptoWrapper = Native.CryptoWrapper;
            this.SSLWrapper = Native.SSLWrapper;
        }
    }
}
