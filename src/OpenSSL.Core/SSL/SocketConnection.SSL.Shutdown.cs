using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;

using OpenSSL.Core.Error;
using OpenSSL.Core.Interop;
using System.IO.Pipelines;

namespace OpenSSL.Core.SSL
{
    public partial class SocketConnection
    {
        public async Task ShutdownSSL(bool biDerictionalShutdown = false)
        {
            if (!this.encryptionEnabled)
                return;

            //TODO: throw exception
            if (!this.TrySetSslState(SslState.Established, SslState.Shutdown))
                return;

            this._receiveFromSocket.Reader.CancelPendingRead();

            int ret_code, result;
            ValueTask<FlushResult> flushResult;
            //it is not mandatory to wait on confirmation from the other peer
            do
            {
                ret_code = this.SSLWrapper.SSL_shutdown(this.sslHandle);
                if ((result = this.SSLWrapper.SSL_get_error(this.sslHandle, ret_code)) == (int)SslError.SSL_ERROR_SSL)
                    throw new OpenSslException();

                if (biDerictionalShutdown && this.Socket.Connected)
                {
                    flushResult = this.WritePending();
                    if (!flushResult.IsCompleted)
                        await flushResult.ConfigureAwait(false);

                    await this.ReadPending((SslError)result).ConfigureAwait(false);
                }
                else if (ret_code < 0)
                {
                    this.CryptoWrapper.ERR_clear_error();
                    break;
                }
            } while (ret_code != 1);

            //cleanup native memory
            this.SSLCleanup();

            //set state to None
            this.TrySetSslState(SslState.Shutdown, SslState.None);

            //continue after state interruption
            this._socketReader.CompleteInterruption();
            this._socketWriter.CompleteInterruption();
        }

        private void SSLCleanup()
        {
            if (!(this.sslHandle is null) && !this.sslHandle.IsInvalid)
            {
                this.sslHandle.Dispose();
                this.sslHandle = null;
            }

            if (!(this.readHandle is null) && !this.readHandle.IsInvalid)
            {
                this.readHandle.Dispose();
                this.readHandle = null;
            }

            if (!(this.writeHandle is null) && !this.writeHandle.IsInvalid)
            {
                this.writeHandle.Dispose();
                this.writeHandle = null;
            }
        }
    }
}
