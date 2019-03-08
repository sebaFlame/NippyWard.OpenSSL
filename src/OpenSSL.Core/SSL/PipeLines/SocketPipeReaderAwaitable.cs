using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.IO.Pipelines;

namespace OpenSSL.Core.SSL.PipeLines
{
    internal class SocketPipeReaderAwaitable : INotifyCompletion
    {
        private SocketConnection SocketConnection;
        private PipeReader SocketReader;
        private CancellationToken CancellationToken;

        private ValueTask<ReadResult> ResultTask;
        private ConfiguredValueTaskAwaitable<ReadResult>.ConfiguredValueTaskAwaiter ReaderAwaitable;
        private ReadResult ReadResult;

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

        public SocketPipeReaderAwaitable(
            PipeReader socketReader, 
            SocketConnection socketConnection)
        {
            this.SocketConnection = socketConnection;
            this.SocketReader = socketReader;

            this.CancellationToken = default;
            this.ReaderAwaitable = default;
            this.CurrentContinuation = null;
            this.ExecutionContext = default;
            this.ReadResult = default;

            this._lock = new object();
            this.ResultDiscarded = false;
        }

        internal SocketPipeReaderAwaitable RunAsync(CancellationToken cancellationToken = default)
        {
            if (!EqualityComparer<ValueTask<ReadResult>>.Default.Equals(this.ResultTask, default))
                throw new InvalidOperationException("Read operation is already in progress");

            lock (this._lock)
            {
                this.CancellationToken = cancellationToken;
                this.ReadResult = default;
                this.ResultTask = this.SocketReader.ReadAsync(this.CancellationToken);
            }

            return this;
        }

        //should always be an awaitable
        internal void Complete()
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
                throw new InvalidOperationException("Current state invalid to force continuation");

            lock (this._lock)
            {
                if (!this.ResultDiscarded)
                    return;
            }

            /* force a new read when already completed
             * previous ReadResult might contain consumed data 
             * it should pass the verification method 
            */

            //complete previous read if it completed successfully
            if (this.ResultTask.IsCompletedSuccessfully)
                this.SocketReader.AdvanceTo(this.ResultTask.Result.Buffer.Start);

            //start a new read, discarding previous result
            lock (this._lock)
                this.ResultTask = this.SocketReader.ReadAsync(this.CancellationToken);

            if (!this.ResultTask.IsCompleted)
            {
                lock (this._lock)
                    this.ReaderAwaitable = this.ResultTask.ConfigureAwait(false).GetAwaiter();

                this.ReaderAwaitable.OnCompleted(this.ContinuationVerification);
            }
            else
                this.FireContinuation();
        }

        public SocketPipeReaderAwaitable GetAwaiter()
        {
            lock (this._lock)
                this.ReaderAwaitable = this.ResultTask.ConfigureAwait(false).GetAwaiter();
            return this;
        }

        public void OnCompleted(Action continuation)
        {
            lock (this._lock)
                this.CurrentContinuation = continuation;

            //set continuation to the verify method
            this.ReaderAwaitable.OnCompleted(this.ContinuationVerification);
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

        public ReadResult GetResult()
        {
            try
            {
                lock (this._lock)
                {
                    if (!EqualityComparer<ReadResult>.Default.Equals(this.ReadResult, default))
                        return this.ReadResult;

                    return (this.ReadResult = this.ResultTask.Result);
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
                this.ReaderAwaitable = default;
                this.CurrentContinuation = null;

                this.ResultDiscarded = false;
                this.ExecutionContext = null;
            }
        }
    }
}
