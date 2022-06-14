using System;
using System.Collections.Generic;
using System.Text;

namespace NippyWard.OpenSSL.Interop.Attributes
{
    /// <summary>
    /// An attribute to pick a correct (generated) SafeHandle type
    /// </summary>
    [AttributeUsage(AttributeTargets.ReturnValue | AttributeTargets.Parameter, AllowMultiple = false)]
    internal class TakeOwnershipAttribute : GeneratorDecaratorAttribute
    { }
}
