using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.Interop.Wrappers
{
    internal interface ISafeHandleFactory
    {
        /// <summary>
        /// Create a new safehandle which (after construction) has the sole reference on the <paramref name="ptr"/>
        /// </summary>
        /// <typeparam name="TSafeHandle">The abstract type of the safehandle</typeparam>
        /// <param name="ptr">The native handle to wrap</param>
        /// <returns>An instance of the <typeparamref name="TSafeHandle"/></returns>
        TSafeHandle CreateNewSafeHandle<TSafeHandle>(IntPtr ptr)
            where TSafeHandle : SafeBaseHandle;

        /// <summary>
        /// Creates a new safe handle containing an extra reference on the <paramref name="ptr"/>.
        /// The extra reference can also be a duplicate (if the contained handle is not a reference type).
        /// </summary>
        /// <typeparam name="TSafeHandle">The abstract type of the safehandle</typeparam>
        /// <param name="ptr">The native handle to wrap</param>
        /// <returns>An instance of the <typeparamref name="TSafeHandle"/></returns>
        TSafeHandle CreateReferenceSafeHandle<TSafeHandle>(IntPtr ptr)
            where TSafeHandle : SafeBaseHandle;

        /// <summary>
        /// Creates a new safe handle as a simple wrapper with no (extra) references.
        /// Disposal does nothing to the <paramref name="ptr"/>.
        /// </summary>
        /// <typeparam name="TSafeHandle">The abstract type of the safehandle</typeparam>
        /// <param name="ptr">The native handle to wrap</param>
        /// <returns>An instance of the <typeparamref name="TSafeHandle"/></returns>
        TSafeHandle CreateWrapperSafeHandle<TSafeHandle>(IntPtr ptr)
            where TSafeHandle : SafeBaseHandle;
    }
}
