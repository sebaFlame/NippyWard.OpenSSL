using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

namespace NippyWard.OpenSSL.SSL
{
    [Flags]
    public enum SslState
    {
        /// <summary>
        /// The SSL context is in a correct state and no action is needed
        /// </summary>
        NONE = 0,
        /// <summary>
        /// The SSL context requires a read from the socket
        /// Please use <see cref="Ssl.ReadSsl(ReadOnlySpan{byte}, Span{byte}, out int, out int)"/>
        /// Please use <see cref="Ssl.ReadSsl(in System.Buffers.ReadOnlySequence{byte}, System.Buffers.IBufferWriter{byte}, out SequencePosition)"/>
        /// Please use <see cref="Ssl.ReadSsl(ReadOnlySpan{byte}, System.Buffers.IBufferWriter{byte}, out int)"/>
        /// With read data from the socket and an empty decryption buffer.
        /// </summary>
        WANTREAD = 1 << 0,
        /// <summary>
        /// The SSL context requires a write to the socket
        /// Please use <see cref="Ssl.WriteSsl(ReadOnlySpan{byte}, Span{byte}, out int, out int)"/>
        /// Please use <see cref="Ssl.WriteSsl(in System.Buffers.ReadOnlySequence{byte}, System.Buffers.IBufferWriter{byte}, out SequencePosition)"/>
        /// Please use <see cref="Ssl.WriteSsl(ReadOnlySpan{byte}, System.Buffers.IBufferWriter{byte}, out int)"/>
        /// With a write buffer to send to socket and an empty encryption buffer
        /// </summary>
        WANTWRITE = 1 << 1,
        /// <summary>
        /// Shutdown has been called from peer, stop reading/writing to allow clean shutdown
        /// </summary>
        SHUTDOWN = 1 << 2,
        /// <summary>
        /// A handshake has completed (either during <see cref="Ssl.DoHandshake(out SslState)"/> or <see cref="Ssl.DoRenegotiate"/>)
        /// Useful to call any callbacks.
        /// </summary>
        HANDSHAKECOMPLETE = 1 << 3,
        /// <summary>
        /// An empty buffer has been passed, no data can be written/read
        /// </summary>
        EMPTYBUFFER = 1 << 4,
        /// <summary>
        /// Shutdown has been received
        /// </summary>
        SHUTDOWN_RECEIVED = 1 << 5,
        /// <summary>
        /// Shutdown has been sent
        /// </summary>
        SHUTDOWN_SENT = 1 << 6
    }

    public static class SslStateExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool WantsWrite(this SslState sslState)
            => (sslState & SslState.WANTWRITE) > 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool WantsRead(this SslState sslState)
            => (sslState & SslState.WANTREAD) > 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool HandshakeCompleted(this SslState sslState)
            => (sslState & SslState.HANDSHAKECOMPLETE) > 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsShutdown(this SslState sslState)
            => (sslState & SslState.SHUTDOWN) > 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool ReceivedEmptyBuffer(this SslState sslState)
            => (sslState & SslState.EMPTYBUFFER) > 0;
    }
}
