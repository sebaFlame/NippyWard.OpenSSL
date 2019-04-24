﻿using System;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace OpenSSL.Core.SSL
{
    /// <summary>
    /// Represents a multi-client socket-server capable of dispatching pipeline clients
    /// </summary>
    public abstract class SocketServer : IDisposable
    {
        public Socket Listener { get; private set; }

        internal SocketConnection.SslContextRefWrapper SslContextWrapper { get; private set; }

        /// <summary>
        /// Start listening as a server
        /// </summary>
        public void Listen(
            EndPoint endPoint,
            AddressFamily addressFamily = AddressFamily.InterNetwork,
            SocketType socketType = SocketType.Stream,
            ProtocolType protocolType = ProtocolType.Tcp,
            PipeOptions sendOptions = null, PipeOptions receiveOptions = null)
        {
            if (Listener != null) throw new InvalidOperationException("Server is already running");
            Socket listener = new Socket(addressFamily, socketType, protocolType);
            listener.Bind(endPoint);
            listener.Listen(20);

            Listener = listener;
            StartOnScheduler(receiveOptions?.ReaderScheduler, _ => FireAndForget(ListenForConnectionsAsync(
                sendOptions ?? PipeOptions.Default, receiveOptions ?? PipeOptions.Default)), null);

            OnStarted(endPoint);
        }

        /// <summary>
        /// Stop listening as a server
        /// </summary>
        public void Stop()
        {
            var socket = Listener;
            Listener = null;
            if (socket != null)
            {
                try { socket.Dispose(); } catch { }
            }
        }

        /// <summary>
        /// Release any resources associated with this instance
        /// </summary>
        public void Dispose()
        {
            Stop();
            Dispose(true);
        }

        /// <summary>
        /// Release any resources associated with this instance
        /// </summary>
        protected virtual void Dispose(bool disposing) { }

        private static void FireAndForget(Task task)
        {
            // make sure that any exception is observed
            if (task == null) return;
            if (task.IsCompleted)
            {
                GC.KeepAlive(task.Exception);
                return;
            }
            task.ContinueWith(t => GC.KeepAlive(t.Exception), TaskContinuationOptions.OnlyOnFaulted);
        }

        /// <summary>
        /// Create a new instance of a socket server
        /// </summary>
        protected SocketServer()
        {
            this.SslContextWrapper = new SocketConnection.SslContextRefWrapper();

            RunClientAsync = async boxed =>
            {
                var client = (ClientConnection)boxed;
                try
                {
                    await OnClientConnectedAsync(client).ConfigureAwait(false);
                    try { client.Transport.Input.Complete(); } catch { }
                    try { client.Transport.Output.Complete(); } catch { }
                }
                catch (Exception ex)
                {
                    try { client.Transport.Input.Complete(ex); } catch { }
                    try { client.Transport.Output.Complete(ex); } catch { }
                    OnClientFaulted(in client, ex);
                }
                finally
                {
                    if (client.Transport is IDisposable d)
                    {
                        try { d.Dispose(); } catch { }
                    }
                }
            };
        }

        private readonly Action<object> RunClientAsync;

        private static void StartOnScheduler(PipeScheduler scheduler, Action<object> callback, object state)
        {
            if (scheduler == PipeScheduler.Inline) scheduler = null;
            (scheduler ?? PipeScheduler.ThreadPool).Schedule(callback, state);
        }

        private async Task ListenForConnectionsAsync(PipeOptions sendOptions, PipeOptions receiveOptions)
        {
            try
            {
                while (true)
                {
                    var clientSocket = await Listener.AcceptAsync().ConfigureAwait(false);
                    SocketConnection.SetRecommendedServerOptions(clientSocket);
                    SocketConnection client = SocketConnection.Create(clientSocket, sendOptions, receiveOptions);
                    client.SslContextWrapper = this.SslContextWrapper;

                    StartOnScheduler(receiveOptions.ReaderScheduler, RunClientAsync,
                        new ClientConnection(client, clientSocket.RemoteEndPoint)); // boxed, but only once per client
                }
            }
            catch (NullReferenceException) { }
            catch (ObjectDisposedException) { }
            catch (Exception ex) { OnServerFaulted(ex); }
        }

        /// <summary>
        /// Invoked when the server has faulted
        /// </summary>
        protected virtual void OnServerFaulted(Exception exception) { }

        /// <summary>
        /// Invoked when a client has faulted
        /// </summary>
        protected virtual void OnClientFaulted(in ClientConnection client, Exception exception) { }

        /// <summary>
        /// Invoked when the server starts
        /// </summary>
        protected virtual void OnStarted(EndPoint endPoint) { }

        /// <summary>
        /// Invoked when a new client connects
        /// </summary>
        protected abstract Task OnClientConnectedAsync(in ClientConnection client);

        /// <summary>
        /// The state of a client connection
        /// </summary>
        protected readonly struct ClientConnection
        {
            public readonly SocketConnection SocketConnection;

            internal ClientConnection(SocketConnection socketConnection, EndPoint remoteEndPoint)
            {
                this.SocketConnection = socketConnection;
                this.Transport = socketConnection;
                this.RemoteEndPoint = remoteEndPoint;
            }

            /// <summary>
            /// The transport to use for this connection
            /// </summary>
            public IDuplexPipe Transport { get; }

            /// <summary>
            /// The remote endpoint that the client connected from
            /// </summary>
            public EndPoint RemoteEndPoint { get; }
        }
    }
}
