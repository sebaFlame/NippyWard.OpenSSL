using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core
{
    internal class WrapperAttribute : Attribute
    {
        internal Type WrapperType { get; private set; }

        internal WrapperAttribute (Type wrapperType)
        {
            this.WrapperType = wrapperType;
        }
    }
}
