using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.Collections
{
    internal interface IStackableWrapper<T> : ISafeHandleWrapper<T>
        where T : SafeBaseHandle, IStackable
    { }
}
