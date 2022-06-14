using System;
using System.Collections.Generic;
using System.Text;

namespace NippyWard.OpenSSL.Error
{
    public class ShutdownException : OpenSslException
    {
        internal ShutdownException()
            : base("Peer requested SSL shutdown") { }
    }
}
