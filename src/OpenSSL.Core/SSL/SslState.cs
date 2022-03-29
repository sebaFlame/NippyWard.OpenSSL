using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenSSL.Core.SSL
{
    public enum SslState
    {
        /// <summary>
        /// The SSL context is in a correct state
        /// </summary>
        NONE = 0,
        /// <summary>
        /// The SSL context requires a read from the socket
        /// Please use <see cref="Ssl.ReadPending"/>
        /// </summary>
        WANTREAD,
        /// <summary>
        /// The SSL context requires a write to the socket
        /// Please use <see cref="Ssl.WritePending"/>
        /// </summary>
        WANTWRITE
    }
}
