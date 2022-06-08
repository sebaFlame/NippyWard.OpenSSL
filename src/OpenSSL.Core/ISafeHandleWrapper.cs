using System;
using System.Runtime.InteropServices;

using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core
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
