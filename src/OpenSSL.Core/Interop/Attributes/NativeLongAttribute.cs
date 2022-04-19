using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenSSL.Core.Interop.Attributes
{
    /// <summary>
    /// An attribute to signify a native long type (not long long).
    /// 4 bytes on windows on x86 & x64!
    /// </summary>
    [AttributeUsage(AttributeTargets.ReturnValue | AttributeTargets.Parameter, AllowMultiple = false)]
    internal class NativeLongAttribute : GeneratorDecaratorAttribute
    { }
}
