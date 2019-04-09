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

        private ExecutionContext ExecutionContext;

        public bool IsCompleted
        {
            get
            {
                lock (this._lock)
                    return this.SocketConnection.IsAvailable(out SslState sslState)
                        && this.CurrentState >= AwaitableState.Running
                        && this.CurrentState < AwaitableState.NotStarted
                        && this.ResultTask.IsCompleted;
            }
        }

        public bool IsCompletedSuccessfully
        {
            get
            {
                lock (this._lock)
                    return this.SocketConnection.IsAvailable(out SslState sslState)
                        && this.CurrentState == AwaitableState.Running
                        && this.ResultTask.IsCompletedSuccessfully;
            }
        }

        public bool IsFaulted
        {
            get
            {
                lock (this._lock)
                    return this.CurrentState == AwaitableState.Running && this.ResultTask.IsFaulted;
            }
        }

        public bool IsCanceled
        {
            get
            {
                lock (this._lock)
                    return this.CurrentState == AwaitableState.Running && this.ResultTask.IsCanceled;
            }
        }

        private Action CurrentContinuation;
        private readonly object _lock;
        private AwaitableState CurrentState;

        public SocketPipeReaderAwaitable(
            PipeReader socketReader, 
            SocketConnection socketConnection)
        {
            this.SocketConnection = socketConnection;
            this.SocketReader = socketReader;

            this.CancellationToken = CancellationToken.None;
            this.CurrentContinuation = null;

            this.CurrentState = AwaitableState.None;
            this._lock = new object();
        }

        internal SocketPipeReaderAwaitable RunAsync(CancellationToken cancellationToken = default)
        {
            lock (this._lock)
            {
                this.CancellationToken = cancellationToken;

                if (!this.SocketConnection.IsAvailable(out SslState sslState))
                {
                    this.CurrentState = AwaitableState.NotStarted;
                }
                else
                {
                    this.ResultTask = this.SocketReader.ReadAsync(this.CancellationToken);
                    this.CurrentState = AwaitableState.Running;
                }
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
                if (this.CurrentState <= AwaitableState.Running)
                    return;
            }

            /* force a new read when already completed
             * previous ReadResult might contain consumed data 
             * it should pass the verification method 
            */

            bool cont = false;
            //start a new read, discarding previous result
            lock (this._lock)
            {
                //TODO: correct?
                if (this.IsCompletedSuccessfully)
                    this.SocketReader.AdvanceTo(this.ResultTask.Result.Buffer.Start);

                this.ResultTask = this.SocketReader.ReadAsync(this.CancellationToken);
                this.CurrentState = AwaitableState.Running;

                if (!this.ResultTask.IsCompleted)
                {
                    if (this.CurrentContinuation is null)
                        throw new InvalidOperationException("Invalid async state");

                    this.ReaderAwaitable = this.ResultTask.ConfigureAwait(false).GetAwaiter();
                    this.ReaderAwaitable.OnCompleted(this.ContinuationVerification);
                }
                else
                    cont = true;
            }

            if (cont)
                this.FireContinuation();
        }

        //TODO: ensure the following 2 methods get executed in succession
        public SocketPipeReaderAwaitable GetAwaiter()
        {
            lock (this._lock)
            {
                if (this.CurrentState == AwaitableState.Running)
                    this.ReaderAwaitable = this.ResultTask.ConfigureAwait(false).GetAwaiter();
            }
            return this;
        }

        public void OnCompleted(Action continuation)
        {
            lock (this._lock)
            {
                if (!(this.CurrentContinuation is null))
                    throw new InvalidOperationException("Double continuation detected");

                this.CurrentContinuation = continuation;

                if(this.CurrentState == AwaitableState.Running)
                    this.ReaderAwaitable.OnCompleted(this.ContinuationVerification);
            }

        }

        private void ContinuationVerification()
        {
            if (!this.SocketConnection.IsAvailable(out SslState sslState))
            {
                lock (this._lock)
                {
                    this.CurrentState = AwaitableState.Interrupted;
                    this.ExecutionContext = ExecutionContext.Capture();
                }
                return;
            }

            lock (this._lock)
            {
                if (!this.ResultTask.IsCompleted)
                {
                    this.CurrentState = AwaitableState.Canceled;
                    this.ExecutionContext = ExecutionContext.Capture();
                    return;
                }
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
                    if (this.CurrentState > AwaitableState.Running)
                        throw new InvalidOperationException($"Current operation in an invalid state: { this.CurrentState }");

                    return this.ResultTask.Result;
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
                this.CancellationToken = CancellationToken.None;
                this.CurrentContinuation = null;
                this.ExecutionContext = null;
            }
        }

        private enum AwaitableState
        {
            None = 0,
            Running = 1,
            Interrupted = 2,
            Canceled = 3,
            NotStarted = 4
        }
    }
}
