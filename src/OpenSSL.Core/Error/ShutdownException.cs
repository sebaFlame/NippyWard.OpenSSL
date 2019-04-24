using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Error
{
    public class ShutdownException : OpenSslException
    {
        internal ShutdownException()
            : base("Peer requested SSL shutdown") { }
    }
}
