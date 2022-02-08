using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.Attributes
{
    //TODO: remove!
    /// <summary>
    /// An attribute to signify that you DO NOT own the returned handle
    /// </summary>
    [AttributeUsage(AttributeTargets.ReturnValue | AttributeTargets.Parameter, AllowMultiple = false)]
    internal class DontTakeOwnershipAttribute : GeneratorDecaratorAttribute
    { }
}
