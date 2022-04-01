using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Generator
{
    internal struct SafeHandleModel
    {
        public string Name { get; }
        public bool IsAbsract { get; }

        public SafeHandleModel
        (
            string name,
            bool isAbstract
        )
        {
            this.Name = name;
            this.IsAbsract = isAbstract;
        }
    }
}
