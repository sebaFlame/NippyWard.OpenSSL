using System;
using System.Collections.Generic;
using System.Text;

using NippyWard.OpenSSL.Interop;
using NippyWard.OpenSSL.Interop.Wrappers;

namespace NippyWard.OpenSSL
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
