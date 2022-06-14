using System;
using System.Collections.Generic;
using System.Text;

namespace NippyWard.OpenSSL.Interop.Attributes
{
    /// <summary>
    /// An attribute to signify you don't want to check the return type
    /// </summary>
    [AttributeUsage(AttributeTargets.ReturnValue | AttributeTargets.Parameter, AllowMultiple = false)]
    internal class DontVerifyTypeAttribute : GeneratorDecaratorAttribute
    { }
}
