using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NippyWard.OpenSSL.Collections
{
    public interface IOpenSslReadOnlyCollection<T>
        : IReadOnlyCollection<T>,
            IDisposable
    { }
}
