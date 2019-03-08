using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.SSL
{
    /// <summary>
    ///
    /// </summary>
    [Flags]
    public enum SslProtocol
    {
        Ssl3 = 1 << 1,
        Tls = 1 << 2,
        Tls11 = 1 << 3,
        Tls12 = 1 << 4,
        Tls13 = 1 << 5
    }
}
