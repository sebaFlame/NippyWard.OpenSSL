using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.SSL.Exceptions
{
    public class SslHandshakeException : Exception
    {
        internal Exception Exception { get; private set; }

        public SslHandshakeException(string message)
            : base(message)
        { }

        public SslHandshakeException(Exception exception)
            : base(exception.Message)
        {
            this.Exception = exception;
        }
    }
}
