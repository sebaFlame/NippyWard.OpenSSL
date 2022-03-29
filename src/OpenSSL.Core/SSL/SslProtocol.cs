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
        Ssl3 = 1 << 0,
        Tls = 1 << 1,
        Tls11 = 1 << 2,
        Tls12 = 1 << 3,
        Tls13 = 1 << 4
    }
}
