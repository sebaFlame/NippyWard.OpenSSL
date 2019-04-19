using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Collections
{
    public interface IOpenSslIList<TOuter> : IOpenSslIEnumerable<TOuter>, IList<TOuter>
        where TOuter : OpenSslWrapperBase
    {
    }
}
