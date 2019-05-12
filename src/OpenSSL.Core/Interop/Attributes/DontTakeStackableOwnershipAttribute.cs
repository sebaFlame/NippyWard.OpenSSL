using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.Attributes
{
    /// <summary>
    /// An attribute to signify that you DO NOT own the returned <see cref="SafeHandles.IStackable"/> handle
    /// </summary>
    [AttributeUsage(AttributeTargets.ReturnValue | AttributeTargets.Parameter, AllowMultiple = false)]
    internal class DontTakeStackableOwnershipAttribute : Attribute
    { }
}
