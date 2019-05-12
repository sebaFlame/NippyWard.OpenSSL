using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.Attributes
{
    /// <summary>
    /// An attribute to override the native method used for this method
    /// The method you use should have the same signature
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    internal class OpenSslNativeMethodAttribute : Attribute
    {
        internal string InterfaceMethodName { get; private set; }

        internal OpenSslNativeMethodAttribute(string interfaceMethod)
        {
            this.InterfaceMethodName = interfaceMethod;
        }
    }
}
