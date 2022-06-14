using System;
using System.Runtime.InteropServices;

using NippyWard.OpenSSL.Interop.SafeHandles;

namespace NippyWard.OpenSSL
{
    public interface ISafeHandleWrapper : IDisposable
    {
        SafeHandle Handle { get; }
    }

    internal interface ISafeHandleWrapper<T> : ISafeHandleWrapper
        where T : SafeBaseHandle
    {
        new T Handle { get; }
    }
}
