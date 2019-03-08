using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.Attributes
{
    /// <summary>
    /// An attribute to pick a correct (generated) SafeHandle type
    /// An abstract class always owns the handle
    /// </summary>
    [AttributeUsage(AttributeTargets.ReturnValue | AttributeTargets.Parameter, AllowMultiple = false)]
    internal class NewSafeHandleAttribute : Attribute
    { }
}
