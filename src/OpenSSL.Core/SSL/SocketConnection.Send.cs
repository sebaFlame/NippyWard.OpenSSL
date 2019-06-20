using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

using OpenSSL.Core.Interop;

namespace OpenSSL.Core.SSL
{
    public partial class SocketConnection
    {
        /// <summary>
        /// The total number of bytes sent to the socket
        /// </summary>
        public long BytesSent => Interlocked.Read(ref _totalBytesSent);

        long IMeasuredDuplexPipe.TotalBytesSent => BytesSent;

        private long _totalBytesSent;

        private SocketAwaitableEventArgs _writerArgs;
        private Task sendTask;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Task DoSendAsync()
        {
            return (this.sendTask = DoSendAsyncInternal());
        }

        private async Task DoSendAsyncInternal()
        {
            Exception error = null;
            DebugLog("starting send loop");
            try
            {
                while (true)
                {
                    DebugLog("awaiting data from pipe...");
                    if (_sendToSocket.Reader.TryRead(out var result))
                    {
                        Helpers.Incr(Counter.SocketPipeReadReadSync);
                    }
                    else
                    {
                        Helpers.Incr(Counter.OpenSendReadAsync);
                        var read = _sendToSocket.Reader.ReadAsync();
                        Helpers.Incr(read.IsCompleted ? Counter.SocketPipeReadReadSync : Counter.SocketPipeReadReadAsync);
                        result = await read;
                        Helpers.Decr(Counter.OpenSendReadAsync);
                    }
                    var buffer = result.Buffer;

                    if (result.IsCanceled || (result.IsCompleted && buffer.IsEmpty))
                    {
                        DebugLog(result.IsCanceled ? "cancelled" : "complete");
                        break;
                    }

                    try
                    {
                        if (!buffer.IsEmpty)
                        {
                            if (_writerArgs == null) _writerArgs = new SocketAwaitableEventArgs(InlineWrites ? null : _sendOptions.ReaderScheduler);
                            DebugLog($"sending {buffer.Length} bytes over socket...");
                            Helpers.Incr(Counter.OpenSendWriteAsync);
                            DoSend(Socket, _writerArgs, buffer, Name);
                            Helpers.Incr(_writerArgs.IsCompleted ? Counter.SocketSendAsyncSync : Counter.SocketSendAsyncAsync);
                            Interlocked.Add(ref _totalBytesSent, await _writerArgs);
                            Helpers.Decr(Counter.OpenSendWriteAsync);
                        }
                        else if (result.IsCompleted)
                        {
                            DebugLog("completed");
                            break;
                        }
                    }
                    finally
                    {
                        DebugLog("advancing");
                        this._sendToSocket.Reader.AdvanceTo(buffer.End);
                        this._sendToSocket.CompleteSend(buffer.Length);
                    }
                }
                TrySetShutdown(PipeShutdownKind.WriteEndOfStream);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.OperationAborted)
            {
                TrySetShutdown(PipeShutdownKind.WriteSocketError, ex.SocketErrorCode);
                DebugLog($"fail: {ex.SocketErrorCode}");
                error = null;
            }
            catch (SocketException ex)
            {
                TrySetShutdown(PipeShutdownKind.WriteSocketError, ex.SocketErrorCode);
                DebugLog($"fail: {ex.SocketErrorCode}");
                error = ex;
            }
            catch (ObjectDisposedException)
            {
                TrySetShutdown(PipeShutdownKind.WriteDisposed);
                DebugLog("fail: disposed");
                error = null;
            }
            catch (IOException ex)
            {
                TrySetShutdown(PipeShutdownKind.WriteIOException);
                DebugLog($"fail - io: {ex.Message}");
                error = ex;
            }
            catch (Exception ex)
            {
                TrySetShutdown(PipeShutdownKind.WriteException);
                DebugLog($"fail: {ex.Message}");
                error = new IOException(ex.Message, ex);
            }
            finally
            {
                // Make sure to close the connection only after the _aborted flag is set.
                // Without this, the RequestsCanBeAbortedMidRead test will sometimes fail when
                // a BadHttpRequestException is thrown instead of a TaskCanceledException.
                _sendAborted = true;
                try
                {
                    DebugLog($"shutting down socket-send");
                    Socket.Shutdown(SocketShutdown.Send);
                }
                catch { }

                // close *both halves* of the send pipe; we're not
                // listening *and* we don't want anyone trying to write
                DebugLog($"marking {nameof(Output)} as complete");
                try { _sendToSocket.Writer.Complete(error); } catch { }
                try { _sendToSocket.Reader.Complete(error); } catch { }

                var args = _writerArgs;
                _writerArgs = null;
                if (args != null) try { args.Dispose(); } catch { }
            }
            DebugLog(error == null ? "exiting with success" : $"exiting with failure: {error.Message}");
            //return error;
        }

        private async Task DoSend(Socket socket, SocketAwaitableEventArgs args, ReadOnlySequence<byte> buffer)
        {
            DebugLog($"sending {buffer.Length} bytes over socket...");
            Helpers.Incr(Counter.OpenSendWriteAsync);
            DoSend(Socket, args, buffer, Name);
            Helpers.Incr(args.IsCompleted ? Counter.SocketSendAsyncSync : Counter.SocketSendAsyncAsync);
            Interlocked.Add(ref _totalBytesSent, await args);
            Helpers.Decr(Counter.OpenSendWriteAsync);
        }

        private async Task DoSendSsl(Socket socket, SocketAwaitableEventArgs args, ReadOnlySequence<byte> buffer, Memory<byte> writeBuffer)
        {
            if (buffer.IsSingleSegment)
                await DoSend(socket, args, buffer.First, writeBuffer).ConfigureAwait(false);
            else
            {
                foreach (ReadOnlyMemory<byte> buf in buffer)
                    await DoSend(socket, args, buf, writeBuffer).ConfigureAwait(false);
            }
        }
        private async Task DoSend(Socket socket, SocketAwaitableEventArgs args, ReadOnlyMemory<byte> readBuffer, Memory<byte> writeBuffer)
        {
            ReadOnlyMemory<byte> sendBuffer;
            int writtenLength = 0;

            do
            {
                sendBuffer = DoSendSsl(readBuffer, writeBuffer, ref writtenLength);
                await DoSend(socket, args, sendBuffer).ConfigureAwait(false);
            } while (writtenLength < readBuffer.Length);
        }

        //TODO: check SSL_error?
        private ReadOnlyMemory<byte> DoSendSsl(ReadOnlyMemory<byte> buf, Memory<byte> writeBuffer, ref int writtenLength)
        {
            int currentlyWritten;

            //encrypt all/partial (SSL_MODE_ENABLE_PARTIAL_WRITE)
            writtenLength += (currentlyWritten = this.SSLWrapper.SSL_write(this.sslHandle, buf.Span.GetPinnableReference(), buf.Length));

            //read what needs to be sent to the other party
            int readLength = this.CryptoWrapper.BIO_read(this.writeHandle, ref writeBuffer.Span.GetPinnableReference(), writeBuffer.Length);

            return writeBuffer.Slice(0, readLength);
        }

        private async Task DoSend(Socket socket, SocketAwaitableEventArgs args, ReadOnlyMemory<byte> buffer)
        {
            DebugLog($"sending {buffer.Length} bytes over socket...");
            Helpers.Incr(Counter.OpenSendWriteAsync);
            DoSend(Socket, args, buffer, Name);
            Helpers.Incr(args.IsCompleted ? Counter.SocketSendAsyncSync : Counter.SocketSendAsyncAsync);
            Interlocked.Add(ref _totalBytesSent, await args);
            Helpers.Decr(Counter.OpenSendWriteAsync);
        }

        private static void DoSend(Socket socket, SocketAwaitableEventArgs args, in ReadOnlySequence<byte> buffer, string name)
        {
            if (buffer.IsSingleSegment)
            {
                DoSend(socket, args, buffer.First, name);
                return;
            }

#if SOCKET_STREAM_BUFFERS
            if (!args.MemoryBuffer.IsEmpty)
#else
            if (args.Buffer != null)
#endif
            {
                args.SetBuffer(null, 0, 0);
            }

            args.BufferList = GetBufferList(args, buffer);

            Helpers.DebugLog(name, $"## {nameof(socket.SendAsync)} {buffer.Length}");
            if (socket.SendAsync(args))
            {
                Helpers.Incr(Counter.SocketSendAsyncMultiAsync);
            }
            else
            {
                Helpers.Incr(Counter.SocketSendAsyncMultiSync);
                args.Complete();
            }
        }

#pragma warning disable RCS1231 // Make parameter ref read-only.
        private static void DoSend(Socket socket, SocketAwaitableEventArgs args, ReadOnlyMemory<byte> memory, string name)
#pragma warning restore RCS1231 // Make parameter ref read-only.
        {
            // The BufferList getter is much less expensive then the setter.
            if (args.BufferList != null)
            {
                args.BufferList = null;
            }

#if SOCKET_STREAM_BUFFERS
            args.SetBuffer(MemoryMarshal.AsMemory(memory));
#else
            var segment = memory.GetArray();

            args.SetBuffer(segment.Array, segment.Offset, segment.Count);
#endif
            Helpers.DebugLog(name, $"## {nameof(socket.SendAsync)} {memory.Length}");
            if (socket.SendAsync(args))
            {
                Helpers.Incr(Counter.SocketSendAsyncSingleAsync);
            }
            else
            {
                Helpers.Incr(Counter.SocketSendAsyncSingleSync);
                args.Complete();
            }
        }

        private static List<ArraySegment<byte>> GetBufferList(SocketAsyncEventArgs args, in ReadOnlySequence<byte> buffer)
        {
            Helpers.Incr(Counter.SocketGetBufferList);
            Debug.Assert(!buffer.IsEmpty);
            Debug.Assert(!buffer.IsSingleSegment);

            var list = (args?.BufferList as List<ArraySegment<byte>>) ?? GetSpareBuffer();

            if (list == null)
            {
                list = new List<ArraySegment<byte>>();
            }
            else
            {
                // Buffers are pooled, so it's OK to root them until the next multi-buffer write.
                list.Clear();
            }

            foreach (var b in buffer)
            {
                list.Add(b.GetArray());
            }

            return list;
        }
    }
}