using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

namespace OpenSSL.Core.SSL
{
    [Flags]
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
        WANTREAD = 1 << 0,
        /// <summary>
        /// The SSL context requires a write to the socket
        /// Please use <see cref="Ssl.WritePending"/>
        /// </summary>
        WANTWRITE = 1 << 1,
        /// <summary>
        /// Shutdown has been called, stop reading/writing to allow clean shutdown
        /// </summary>
        SHUTDOWN = 1 << 2
    }

    public static class SslStateExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool WantsWrite(this SslState sslState)
            => (sslState & SslState.WANTWRITE) > 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool WantsRead(this SslState sslState)
            => (sslState & SslState.WANTREAD) > 0;
    }
}
