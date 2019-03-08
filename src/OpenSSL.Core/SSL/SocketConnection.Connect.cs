using System;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Diagnostics;

namespace OpenSSL.Core.SSL
{
    public partial class SocketConnection
    {
        /// <summary>
        /// Open a new or existing socket as a client
        /// </summary>
        public static Task<SocketConnection> ConnectAsync(
            EndPoint endpoint,
            PipeOptions pipeOptions = null,
            SocketConnectionOptions connectionOptions = SocketConnectionOptions.None,
            Func<SocketConnection, Task> onConnected = null,
            Socket socket = null, string name = null)
            => ConnectAsync(endpoint, pipeOptions, pipeOptions, connectionOptions, onConnected, socket, name);

        /// <summary>
        /// Open a new or existing socket as a client
        /// </summary>
        public static async Task<SocketConnection> ConnectAsync(
            EndPoint endpoint,
            PipeOptions sendPipeOptions, PipeOptions receivePipeOptions,
            SocketConnectionOptions connectionOptions = SocketConnectionOptions.None,
            Func<SocketConnection, Task> onConnected = null,
            Socket socket = null, string name = null)
        {
            AssertDependencies();

            if (sendPipeOptions == null) sendPipeOptions = PipeOptions.Default;
            if (receivePipeOptions == null) receivePipeOptions = PipeOptions.Default;

            if (socket is null)
                socket = InitializeSocket(endpoint);

            SetRecommendedClientOptions(socket);

            await ConnectAsync(socket, endpoint, connectionOptions, name).ConfigureAwait(false);

            Helpers.DebugLog(name, "connected");

            var connection = Create(socket, sendPipeOptions, receivePipeOptions, connectionOptions, name);

            if (onConnected != null) await onConnected(connection).ConfigureAwait(false);

            return connection;
        }

        private static Socket InitializeSocket(EndPoint endPoint)
        {
            var addressFamily = endPoint.AddressFamily == AddressFamily.Unspecified ? AddressFamily.InterNetwork : endPoint.AddressFamily;
            var protocolType = addressFamily == AddressFamily.Unix ? ProtocolType.Unspecified : ProtocolType.Tcp;
            return new Socket(addressFamily, SocketType.Stream, protocolType);
        }

        private static async Task ConnectAsync(Socket socket, EndPoint endpoint, SocketConnectionOptions connectionOptions, string name)
        {
            using (var args = new SocketAwaitableEventArgs((connectionOptions & SocketConnectionOptions.InlineConnect) == 0 ? PipeScheduler.ThreadPool : null))
            {
                args.RemoteEndPoint = endpoint;
                Helpers.DebugLog(name, $"connecting to {endpoint}...");

                if (!socket.ConnectAsync(args)) args.Complete();
                await args;
            }
        }

        public async Task ConnectAsync()
        {
            if (this.Socket is null)
                throw new NullReferenceException("Socket has not been assigned");

            EndPoint endPoint = this.Socket.RemoteEndPoint;

            this.Reset();

            await ConnectAsync(this.Socket, endPoint, this.SocketConnectionOptions, this.Name).ConfigureAwait(false);

            this.InitializeDefaultThreads();
        }

        internal static void SetFastLoopbackOption(Socket socket)
        {
            // SIO_LOOPBACK_FAST_PATH (https://msdn.microsoft.com/en-us/library/windows/desktop/jj841212%28v=vs.85%29.aspx)
            // Speeds up localhost operations significantly. OK to apply to a socket that will not be hooked up to localhost,
            // or will be subject to WFP filtering.
            const int SIO_LOOPBACK_FAST_PATH = -1744830448;

            // windows only
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                // Win8/Server2012+ only
                var osVersion = Environment.OSVersion.Version;
                if (osVersion.Major > 6 || (osVersion.Major == 6 && osVersion.Minor >= 2))
                {
                    byte[] optionInValue = BitConverter.GetBytes(1);
                    socket.IOControl(SIO_LOOPBACK_FAST_PATH, optionInValue, null);
                }
            }
        }
    }
}
