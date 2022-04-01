using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Generator
{
    internal struct SafeStackHandleModel
    {
        public string Name { get; }
        public string[] GenericTypeParameters { get; }
        public string[] GenericTypeConstraints { get; }

        internal SafeStackHandleModel
        (
            string name, 
            string[] typeParameters,
            string[] genericTypeConstraints
        )
        {
            this.Name = name;
            this.GenericTypeParameters = typeParameters;
            this.GenericTypeConstraints = genericTypeConstraints;
        }
    }
}
