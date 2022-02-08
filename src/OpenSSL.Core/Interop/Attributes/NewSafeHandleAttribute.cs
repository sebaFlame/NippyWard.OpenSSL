using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.Attributes
{
    /// <summary>
    /// An attribute to pick a correct (generated) SafeHandle type
    /// </summary>
    [AttributeUsage(AttributeTargets.ReturnValue | AttributeTargets.Parameter, AllowMultiple = false)]
    internal class NewSafeHandleAttribute : GeneratorDecaratorAttribute
    { }
}
