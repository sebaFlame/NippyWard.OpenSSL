using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.IO.Pipelines;

namespace OpenSSL.Core.SSL.PipeLines
{
    internal class SocketPipeWriterAwaitable : INotifyCompletion
    {
        private SocketConnection SocketConnection;
        private PipeWriter SocketWriter;
        private CancellationToken CancellationToken;

        private ValueTask<FlushResult> ResultTask;
        private ConfiguredValueTaskAwaitable<FlushResult>.ConfiguredValueTaskAwaiter WriterAwaitable;
        private FlushResult FlushResult;

        private ExecutionContext ExecutionContext;

        public bool IsCompleted =>
            this.SocketConnection.IsAvailable(out SslState sslState)
            && this.ResultTask.IsCompleted;

        public bool IsCompletedSuccessfully =>
            this.SocketConnection.IsAvailable(out SslState sslState)
            && this.ResultTask.IsCompletedSuccessfully;

        public bool IsFaulted => this.ResultTask.IsFaulted;
        public bool IsCanceled => this.ResultTask.IsCanceled;

        private Action CurrentContinuation;
        private bool ResultDiscarded;
        private readonly object _lock;

        public SocketPipeWriterAwaitable(
            PipeWriter inputWriter,
            SocketConnection socketConnection)
        {
            this.SocketConnection = socketConnection;
            this.SocketWriter = inputWriter;

            this.CancellationToken = default;
            this.WriterAwaitable = default;
            this.CurrentContinuation = null;
            this.ExecutionContext = default;

            this._lock = new object();
            this.ResultDiscarded = false;
        }

        internal SocketPipeWriterAwaitable RunAsync(CancellationToken cancellationToken = default)
        {
            if (!EqualityComparer<ValueTask<FlushResult>>.Default.Equals(this.ResultTask, default))
                throw new InvalidOperationException("Flush operation is already in progress");

            lock (this._lock)
            {
                this.CancellationToken = cancellationToken;
                this.FlushResult = default;
                this.ResultTask = this.SocketWriter.FlushAsync(this.CancellationToken);
            }

            return this;
        }

        internal void Complete()
        {
            lock (this._lock)
            {
                if (!this.ResultDiscarded)
                    return;
            }

            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException("Current state invalid to force continuation");

            //do not force a new flush, when flushed
            this.FireContinuation();
        }

        public SocketPipeWriterAwaitable GetAwaiter()
        {
            lock (this._lock)
                this.WriterAwaitable = this.ResultTask.ConfigureAwait(false).GetAwaiter();
            return this;
        }

        public void OnCompleted(Action continuation)
        {
            lock (this._lock)
                this.CurrentContinuation = continuation;

            //set continuation to the verify method
            this.WriterAwaitable.OnCompleted(this.ContinuationVerification);
        }

        private void ContinuationVerification()
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
            {
                lock (this._lock)
                {
                    this.ResultDiscarded = true;
                    this.ExecutionContext = ExecutionContext.Capture();
                }
                return;
            }

            this.CurrentContinuation();
        }

        private void FireContinuation()
        {
            Action continuation;
            ExecutionContext ec;

            lock (this._lock)
            {
                continuation = this.CurrentContinuation;
                ec = this.ExecutionContext;
            }

            if (continuation is null)
                return;

            if (ec is null)
                return;

            ExecutionContext.Run(ec, this.CallbackContextWrapper, continuation);
        }

        private void CallbackContextWrapper(object state)
        {
            Action continuation = (Action)state;
            continuation();
        }

        public FlushResult GetResult()
        {
            try
            {
                lock (this._lock)
                {
                    if (!EqualityComparer<FlushResult>.Default.Equals(this.FlushResult, default))
                        return this.FlushResult;

                    return (this.FlushResult = this.ResultTask.Result);
                }
            }
            finally
            {
                this.ResetStateOnCompletion();
            }
        }

        private void ResetStateOnCompletion()
        {
            lock (this._lock)
            {
                this.CancellationToken = default;
                this.ResultTask = default;
                this.WriterAwaitable = default;
                this.CurrentContinuation = null;

                this.ResultDiscarded = false;
                this.ExecutionContext = null;
            }
        }
    }
}
