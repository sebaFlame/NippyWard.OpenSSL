using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;

namespace OpenSSL.Core.SSL.PipeLines
{
    //based on https://github.com/kkokosa/PooledValueTaskSource/
    /// <summary>
    /// WARNING
    /// NOT thread safe
    /// </summary>
    internal class SocketPipeWriterValueTaskSource : IValueTaskSource<FlushResult>
    {
        private enum SocketPipeWriterValueTaskState
        {
            None,
            Running,
            InputFlushed,
            InputRead,
            SocketFlushed
        }

        private SocketPipeWriter SocketPipeWriter;
        private SocketConnection SocketConnection;
        private PipeWriter SocketWriter;
        private Pipe InputPipe;

        private CancellationToken CancellationToken;
        private SocketPipeWriterValueTaskState CurrentState;
        private SocketPipeWriterAwaitable InputResultTask;
        private ValueTask<ReadResult> ReadResultTask;
        private ValueTask<FlushResult> SocketResultTask;
        private FlushResult FlushResult;

        private Action<object> CurrentContinuation;
        private SynchronizationContext SynchronizationContext;
        private ExecutionContext ExecutionContext;
        private object State;

        private Exception Exception;
        private readonly object _lock = new object(); //lock to protect all reusable fields

        public SocketPipeWriterValueTaskSource(
            SocketPipeWriter socketPipeWriter,
            SocketConnection socketConnection,
            PipeWriter socketWriter,
            Pipe inputPipe)
        {
            this.SocketPipeWriter = socketPipeWriter;
            this.SocketConnection = socketConnection;
            this.SocketWriter = socketWriter;
            this.InputPipe = inputPipe;

            this.CancellationToken = default;

            this.CurrentContinuation = default;
            this.SynchronizationContext = default;
            this.ExecutionContext = default;
            this.State = default;

            this.CurrentState = SocketPipeWriterValueTaskState.None;
            this.InputResultTask = new SocketPipeWriterAwaitable(this.InputPipe.Writer, this.SocketConnection);
        }

        public void CompleteInterruption()
        {
            lock (this._lock)
            {
                if (!EqualityComparer<SocketPipeWriterAwaitable>.Default.Equals(this.InputResultTask, default))
                    this.InputResultTask.Complete();
            }
        }

        //TODO: enforce 1 write at a time
        public ValueTask<FlushResult> RunAsync(CancellationToken cancellationToken = default)
        {
            lock (this._lock)
            {
                if (this.CurrentState >= SocketPipeWriterValueTaskState.Running)
                    throw new InvalidOperationException("Flush operation is already in progress");

                this.CurrentState = SocketPipeWriterValueTaskState.Running;
                this.FlushResult = default;
                this.CancellationToken = cancellationToken;
            }

            //synchronous return path
            if (this.FlushInputPipe(out Exception exception)) // try sync socket read
            {
                try
                {
                    if (!(this.Exception is null))
                        throw new AggregateException(this.Exception);

                    return new ValueTask<FlushResult>(this.FlushResult);
                }
                finally
                {
                    this.ResetStateOnCompletion();
                }
            }

            //return awaitable valuetask
            return new ValueTask<FlushResult>(this, 0);
        }

        #region Flush input pipe
        internal bool FlushInputPipe(out Exception exception)
        {
            exception = null;

            this.InputResultTask.RunAsync(this.CancellationToken);

            if (this.InputResultTask.IsCompleted)
            {
                if (this.VerifyFlushInputPipe(this.InputResultTask, out exception))
                {
                    if ((this.Exception = exception) is null)
                    {
                        lock (this._lock)
                            this.CurrentState = SocketPipeWriterValueTaskState.InputFlushed;
                        return this.ReadFromInputPipe(out exception);
                    }
                    else
                        return true; //exception -> halt execution
                }
            }

            this.InputResultTask.GetAwaiter();
            this.InputResultTask.OnCompleted(this.FlushInputPipeContinuation);

            return false;
        }

        private bool VerifyFlushInputPipe(in SocketPipeWriterAwaitable flushResultValueTask, out Exception exception)
        {
            exception = null;
            try
            {
                FlushResult flushResult = flushResultValueTask.GetResult();

                if (flushResultValueTask.IsCompletedSuccessfully)
                    return true;
                else if (flushResultValueTask.IsFaulted)
                    throw new InvalidOperationException("Writer flush operation has failed");
                else if (flushResultValueTask.IsCanceled)
                    throw new OperationCanceledException("Writer flush has been canceled");
                
                if (!flushResult.IsCompleted)
                    throw new InvalidOperationException("Writer flush has not been completed succesfully");
                else if (flushResult.IsCanceled)
                    throw new OperationCanceledException("Writer flush has been canceled");
            }
            catch (Exception ex)
            {
                //do not throw for async path
                exception = ex;
                return true;
            }

            return false;
        }

        internal void FlushInputPipeContinuation()
        {
            Exception exception;

            if (this.VerifyFlushInputPipe(this.InputResultTask, out exception))
            {
                if (!((this.Exception = exception) is null))
                {
                    lock (this._lock)
                        this.CurrentState = SocketPipeWriterValueTaskState.InputFlushed;

                    if (this.ReadFromInputPipe(out exception))
                        this.FireContinuation();
                }
                else
                    this.FireContinuation(); //exception
            }
            else
            {
                //should never happen
                this.Exception = new InvalidOperationException("Unknown error");
                this.FireContinuation();
            }
        }
        #endregion

        #region read input pipe
        //should ALWAYS be synchronous???
        private bool ReadFromInputPipe(out Exception exception)
        {
            exception = null;

            lock (this._lock)
                this.ReadResultTask = this.InputPipe.Reader.ReadAsync(this.CancellationToken);

            if (this.ReadResultTask.IsCompleted)
            {
                if (this.ConsumeInputReadResult(this.ReadResultTask, out exception))
                {
                    if ((this.Exception = exception) is null)
                    {
                        lock (this._lock)
                            this.CurrentState = SocketPipeWriterValueTaskState.InputRead;
                        return this.FlushSocketPipe(out exception);
                    }
                    else
                        return true;
                }
            }

            //build method
            ConfiguredValueTaskAwaitable<ReadResult>.ConfiguredValueTaskAwaiter readAwaitable = this.ReadResultTask.ConfigureAwait(false).GetAwaiter();
            readAwaitable.OnCompleted(this.InputPipeReaderContinuation);

            return false;
        }

        private void InputPipeReaderContinuation()
        {
            Exception exception;
            if (this.ConsumeInputReadResult(this.ReadResultTask, out exception))
            {
                if ((this.Exception = exception) is null)
                {
                    lock (this._lock)
                        this.CurrentState = SocketPipeWriterValueTaskState.InputRead;
                    if (this.FlushSocketPipe(out exception))
                        this.FireContinuation();
                }
                else
                    this.FireContinuation(); //exception
            }
            else
            {
                //should never happen
                this.Exception = new InvalidOperationException("Unknown error");
                this.FireContinuation();
            }
        }

        private bool VerifyInputReadResult(in ValueTask<ReadResult> readresultValueTask, out ReadResult readResult, out Exception exception)
        {
            exception = null;
            try
            {
                readResult = readresultValueTask.Result; //should throw the exception????

                if (readresultValueTask.IsCompletedSuccessfully)
                    return true;
                else if (readresultValueTask.IsFaulted)
                    throw new InvalidOperationException("Reader read operation has failed");
                else if (readresultValueTask.IsCanceled)
                    throw new OperationCanceledException("Reader read has been canceled");

                if (!readResult.IsCompleted)
                    throw new InvalidOperationException("Reader read has not been completed succesfully");
                if (readResult.IsCanceled)
                    throw new OperationCanceledException("Reader read has been canceled");
            }
            catch (Exception ex)
            {
                //do not throw for async path
                exception = ex;
                return true;
            }

            return false;
        }

        public bool ConsumeInputReadResult(in ValueTask<ReadResult> readresultValueTask, out Exception exception)
        {
            if (!this.VerifyInputReadResult(readresultValueTask, out ReadResult readResult, out exception))
            {
                this.Exception = new InvalidOperationException("Unknown error");
                return true;
            }

            if (!((this.Exception = exception) is null))
                return true;

            this.SocketConnection.IsAvailable(out SslState sslState);
            try
            {
                return this.SocketPipeWriter.ConsumeInputReadResult(sslState, readResult, this.CancellationToken);
            }
            catch (Exception ex)
            {
                this.Exception = exception = ex;
                return true;
            }
        }
        #endregion

        #region Flush socket pipe
        internal bool FlushSocketPipe(out Exception exception)
        {
            exception = null;

            lock (this._lock)
                this.SocketResultTask = this.SocketWriter.FlushAsync(this.CancellationToken);

            if (this.SocketResultTask.IsCompleted)
            {
                if (this.VerifyFlushSocketPipe(this.SocketResultTask, out exception))
                {
                    if ((this.Exception = exception) is null)
                    {
                        lock (this._lock)
                            this.CurrentState = SocketPipeWriterValueTaskState.SocketFlushed;
                    }

                    return true;
                }
            }

            ConfiguredValueTaskAwaitable<FlushResult>.ConfiguredValueTaskAwaiter flushAwaitable = this.SocketResultTask.ConfigureAwait(false).GetAwaiter();
            flushAwaitable.OnCompleted(this.FlushSocketPipeContinuation);

            return false;
        }

        private bool VerifyFlushSocketPipe(in ValueTask<FlushResult> flushResultValueTask, out Exception exception)
        {
            exception = null;
            try
            {
                lock (this._lock)
                    this.FlushResult = flushResultValueTask.Result;

                if (flushResultValueTask.IsCompletedSuccessfully)
                    return true;
                else if (flushResultValueTask.IsFaulted)
                    throw new InvalidOperationException("Writer flush operation has failed");
                else if (flushResultValueTask.IsCanceled)
                    throw new OperationCanceledException("Writer flush has been canceled");

                if (!this.FlushResult.IsCompleted)
                    throw new InvalidOperationException("Writer flush has not been completed succesfully");
                else if (this.FlushResult.IsCanceled)
                    throw new OperationCanceledException("Writer flush has been canceled");
            }
            catch (Exception ex)
            {
                //do not throw for async path
                exception = ex;
                return true;
            }

            return false;
        }

        internal void FlushSocketPipeContinuation()
        {
            Exception exception;

            if (this.VerifyFlushSocketPipe(this.SocketResultTask, out exception))
            {
                if (!((this.Exception = exception) is null))
                {
                    lock (this._lock)
                        this.CurrentState = SocketPipeWriterValueTaskState.SocketFlushed;
                }
                this.FireContinuation();
            }
            else
            {
                //should never happen
                this.Exception = new InvalidOperationException("Unknown error");
                this.FireContinuation();
            }
        }
        #endregion

        #region IValueTaskSource
        public ValueTaskSourceStatus GetStatus(short token)
        {
            if (!(this.Exception is null))
                return ValueTaskSourceStatus.Faulted;

            if (this.CurrentState < SocketPipeWriterValueTaskState.SocketFlushed)
                return ValueTaskSourceStatus.Pending;

            return ValueTaskSourceStatus.Succeeded;
        }

        private void FireContinuation()
        {
            ExecutionContext ec = this.ExecutionContext;
            if (ec is null)
                this.InvokeContinuation(this.CurrentContinuation, this.State);
            else
                ExecutionContext.Run(ec, this.CallbackContextWrapper, this.State);
        }

        private void CallbackContextWrapper(object state)
        {
            this.InvokeContinuation(this.CurrentContinuation, this.State);
        }

        public void OnCompleted(Action<object> continuation, object state, short token, ValueTaskSourceOnCompletedFlags flags)
        {
            lock (this._lock)
            {
                //might be completed at this point
                if (this.GetStatus(0) == ValueTaskSourceStatus.Succeeded)
                {
                    continuation(state);
                    return;
                }

                if ((flags & ValueTaskSourceOnCompletedFlags.FlowExecutionContext) != 0)
                {
                    this.ExecutionContext = ExecutionContext.Capture();
                }

                if ((flags & ValueTaskSourceOnCompletedFlags.UseSchedulingContext) != 0)
                {
                    this.SynchronizationContext = SynchronizationContext.Current;
                }

                // Remember current state
                this.State = state;
                this.CurrentContinuation = continuation;
            }
        }

        private void InvokeContinuation(Action<object> continuation, object state)
        {
            if (continuation is null)
                return;

            if (!(this.SynchronizationContext is null))
                this.SynchronizationContext.Post(this.ContinuationWrapper, state);
            else
                continuation(state);
        }

        private void ContinuationWrapper(object state)
        {
            this.CurrentContinuation(state);
        }

        public FlushResult GetResult(short token)
        {
            try
            {
                lock (this._lock)
                {
                    if (!(this.Exception is null))
                        throw new AggregateException(this.Exception);

                    if (EqualityComparer<FlushResult>.Default.Equals(this.FlushResult, default))
                        throw new InvalidOperationException("Result has not been computed yet");
                }

                return this.FlushResult;
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
                this.CurrentState = SocketPipeWriterValueTaskState.None;
                this.SocketResultTask = default;
                this.InputResultTask = default;
                this.ReadResultTask = default;
                this.CancellationToken = default;

                this.ExecutionContext = null;
                this.SynchronizationContext = null;
                this.CurrentContinuation = null;
                this.State = null;
                this.Exception = null;
            }
        }
        #endregion
    }
}
