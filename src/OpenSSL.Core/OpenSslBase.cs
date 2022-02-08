using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core
{
    public abstract class OpenSslBase
    {
        internal readonly static ILibCryptoWrapper CryptoWrapper;
        internal readonly static ILibSSLWrapper SSLWrapper;
        internal readonly static IStackWrapper StackWrapper;
        internal readonly static ISafeHandleFactory SafeHandleFactory;

        static OpenSslBase()
        {
            CryptoWrapper = Native.CryptoWrapper;
            SSLWrapper = Native.SSLWrapper;
            StackWrapper = Native.StackWrapper;
            SafeHandleFactory = Native.SafeHandleFactory;
        }
    }
}
