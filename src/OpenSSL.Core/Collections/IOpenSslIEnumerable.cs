using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Collections
{
    public interface IOpenSslIEnumerable<TOuter> : ISafeHandleWrapper, IEnumerable<TOuter>, IDisposable
        where TOuter : OpenSslWrapperBase
    {
    }
}
