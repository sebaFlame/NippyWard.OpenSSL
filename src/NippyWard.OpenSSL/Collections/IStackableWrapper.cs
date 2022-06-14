using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NippyWard.OpenSSL.Interop.SafeHandles;

namespace NippyWard.OpenSSL.Collections
{
    internal interface IStackableWrapper<T> : ISafeHandleWrapper<T>
        where T : SafeBaseHandle, IStackable
    { }
}
