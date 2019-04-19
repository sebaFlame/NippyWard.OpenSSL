using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Collections
{
    public interface IOpenSslIReadOnlyCollection<TOuter> : IOpenSslIEnumerable<TOuter>, IReadOnlyCollection<TOuter>
        where TOuter : OpenSslWrapperBase
    {
    }
}
