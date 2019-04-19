using System;
using System.Runtime.InteropServices;

namespace OpenSSL.Core
{
    public interface ISafeHandleWrapper : IDisposable
    {
        SafeHandle Handle { get; }
    }
}
