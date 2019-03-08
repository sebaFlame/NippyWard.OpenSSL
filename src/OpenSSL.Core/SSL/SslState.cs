using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.SSL
{
    internal enum SslState
    {
        None,
        Established,
        Handshake,
        Renegotiate,
        Shutdown
    }
}
