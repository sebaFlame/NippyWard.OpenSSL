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
    internal class SocketPipeReaderValueTaskSource : IValueTaskSource<ReadResult>
    {
        private enum SocketPipeReaderValueTaskState
        {
            None,
            Running,
            ReadFrame,
            Flushed,
            ReadOutputPipe
        }

        private readonly SocketPipeReader SocketPipeReader;
        private readonly SocketConnection SocketConnection;
        private readonly PipeReader SocketReader;
        private readonly Pipe OutputPipe;

        private CancellationToken CancellationToken;
        private SocketPipeReaderValueTaskState CurrentState;
        private SocketPipeReaderAwaitable SocketResultTask;
        private ValueTask<FlushResult> FlushResultTask;
        private ValueTask<ReadResult> ReadResultTask;
        private ReadResult ReadResult;

        private Action<object> CurrentContinuation;
        private SynchronizationContext SynchronizationContext;
        private ExecutionContext ExecutionContext;
        private object State;

        private Exception Exception;
        private readonly object _lock = new object(); //lock to protect all reusable fields

        public SocketPipeReaderValueTaskSource(
            SocketPipeReader socketPipeReader,
            SocketConnection socketConnection,
            PipeReader socketReader,
            Pipe outputPipe)
        {
            this.SocketPipeReader = socketPipeReader;
            this.SocketConnection = socketConnection;
            this.SocketReader = socketReader;
            this.OutputPipe = outputPipe;

            this.CancellationToken = default;
            this.FlushResultTask = default;
            this.ReadResultTask = default;

            this.CurrentContinuation = default;
            this.SynchronizationContext = default;
            this.ExecutionContext = default;
            this.State = default;

            this.CurrentState = SocketPipeReaderValueTaskState.None;

            this.SocketResultTask = new SocketPipeReaderAwaitable(this.SocketReader, this.SocketConnection);
        }

        public void CompleteInterruption()
        {
            lock (this._lock)
            {
                if (!EqualityComparer<SocketPipeReaderAwaitable>.Default.Equals(this.SocketResultTask, default))
                    this.SocketResultTask.Complete();
            }
        }

        //TODO: enforce 1 read at a time
        public ValueTask<ReadResult> RunAsync(CancellationToken cancellationToken = default)
        {
            lock (this._lock)
            {
                if (this.CurrentState >= SocketPipeReaderValueTaskState.Running)
                    throw new InvalidOperationException("Flush operation is already in progress");

                this.CurrentState = SocketPipeReaderValueTaskState.Running;
                this.ReadResult = default;
                this.CancellationToken = cancellationToken;
            }

            //synchronous return path
            if (this.ReadFromSocket(out Exception exception)) // try sync socket read
            {
                try
                {
                    if (!(this.Exception is null))
                        throw new AggregateException(this.Exception);

                    return new ValueTask<ReadResult>(this.ReadResult);
                }
                finally
                {
                    this.ResetStateOnCompletion();
                }
            }

            //return awaitable valuetask
            return new ValueTask<ReadResult>(this, 0);
        }

        #region Socket read
        public bool ReadFromSocket(out Exception exception)
        {
            exception = null;
            bool completedSync = true;

            //loop untill atleast 1 SSL frame has been read
            do
            {
                this.SocketResultTask.RunAsync(this.CancellationToken);

                //if not completed, start async operation
                if (!this.SocketResultTask.IsCompleted)
                {
                    completedSync = false;
                    break;
                }

            } while (!this.ConsumeSocketReadResult(this.SocketResultTask, out exception));

            if (completedSync)
            {
                if(exception is null)
                    return this.FlushWriter(out exception); //success
                else
                    return true; //exception
            }

            this.SocketResultTask.GetAwaiter();
            this.SocketResultTask.OnCompleted(this.SocketReadContinuation);

            return false;
        }

        private void SocketReadContinuation()
        {
            Exception exception;

            if (!this.ConsumeSocketReadResult(this.SocketResultTask, out exception)) //retry to read full frame
            {
                if(this.ReadFromSocket(out exception))
                    this.FireContinuation();
            }
            else if(!(exception is null)) //exception
                this.FireContinuation();
            else if (this.FlushWriter(out exception)) //success
                this.FireContinuation();
        }

        public bool ConsumeSocketReadResult(in SocketPipeReaderAwaitable socketPipeReaderAwaitable, out Exception exception)
        {
            if (!this.VerifySocketReadResult(socketPipeReaderAwaitable, out ReadResult readResult, out exception))
            {
                this.Exception = new InvalidOperationException("Unknown error");
                return true;
            }

            if (!((this.Exception = exception) is null))
                return true;

            this.SocketConnection.IsAvailable(out SslState sslState);
            try
            {
                if (this.SocketPipeReader.ConsumeSocketReadResult(sslState, readResult, this.CancellationToken))
                {
                    lock(this._lock)
                        this.CurrentState = SocketPipeReaderValueTaskState.ReadFrame;
                    return true;
                }
            }
            catch (Exception ex)
            {
                this.Exception = exception = ex;
                return true;
            }

            return false;
        }

        private bool VerifySocketReadResult(in SocketPipeReaderAwaitable socketPipeReaderAwaitable, out ReadResult readResult, out Exception exception)
        {
            exception = null;
            try
            {
                readResult = socketPipeReaderAwaitable.GetResult(); //should throw the exception????

                if (socketPipeReaderAwaitable.IsCompletedSuccessfully)
                    return true;
                else if (socketPipeReaderAwaitable.IsFaulted)
                    throw new InvalidOperationException("Writer flush operation has failed");
                else if (socketPipeReaderAwaitable.IsCanceled)
                    throw new OperationCanceledException("Writer flush has been canceled");

                if (!readResult.IsCompleted)
                    throw new InvalidOperationException("Writer flush has not been completed succesfully");
                if (readResult.IsCanceled)
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
        #endregion

        #region writer flush
        private bool FlushWriter(out Exception exception)
        {
            exception = null;

            lock (this._lock)
                this.FlushResultTask = this.OutputPipe.Writer.FlushAsync(this.CancellationToken);

            if (this.FlushResultTask.IsCompleted)
            {
                if (this.VerifyFlushResult(this.FlushResultTask, out exception))
                {
                    if ((this.Exception = exception) is null)
                    {
                        lock (this._lock)
                            this.CurrentState = SocketPipeReaderValueTaskState.Flushed;
                        return this.ReadFromOutputPipe(out exception);
                    }
                    else
                        return true; //exception -> halt execution
                }
            }

            ConfiguredValueTaskAwaitable<FlushResult>.ConfiguredValueTaskAwaiter flushAwaitable = this.FlushResultTask.ConfigureAwait(false).GetAwaiter();
            flushAwaitable.OnCompleted(this.WriterFlushContinuation);

            return false;
        }

        private void WriterFlushContinuation()
        {
            Exception exception;

            if (this.VerifyFlushResult(this.FlushResultTask, out exception))
            {
                if (!((this.Exception = exception) is null))
                {
                    lock (this._lock)
                        this.CurrentState = SocketPipeReaderValueTaskState.Flushed;

                    if (this.ReadFromOutputPipe(out exception))
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

        private bool VerifyFlushResult(in ValueTask<FlushResult> flushResultValueTask, out Exception exception)
        {
            exception = null;
            try
            {
                FlushResult flushResult = flushResultValueTask.Result; //should throw the exception????

                if (flushResultValueTask.IsCompletedSuccessfully)
                    return true;
                else if (flushResultValueTask.IsFaulted)
                    throw new InvalidOperationException("Writer flush operation has failed");
                else if (flushResultValueTask.IsCanceled)
                    throw new OperationCanceledException("Writer flush has been canceled");

                if(!flushResult.IsCompleted)
                    throw new InvalidOperationException("Writer flush has not been completed succesfully");
                if (flushResult.IsCanceled)
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
        #endregion

        #region reader read
        private bool ReadFromOutputPipe(out Exception exception)
        {
            exception = null;

            lock (this._lock)
                this.ReadResultTask = this.OutputPipe.Reader.ReadAsync(this.CancellationToken);

            if (this.ReadResultTask.IsCompleted)
            {
                if (this.VerifyOutputReadResult(this.ReadResultTask, out exception))
                {
                    if((this.Exception = exception) is null)
                    {
                        lock (this._lock)
                            this.CurrentState = SocketPipeReaderValueTaskState.ReadOutputPipe;
                    }
                    
                    return true;
                }
            }

            //build method
            ConfiguredValueTaskAwaitable<ReadResult>.ConfiguredValueTaskAwaiter readAwaitable = this.ReadResultTask.ConfigureAwait(false).GetAwaiter();
            readAwaitable.OnCompleted(this.OutputPipeReaderContinuation);

            return false;
        }

        private void OutputPipeReaderContinuation()
        {
            Exception exception;
            if (this.VerifyOutputReadResult(this.ReadResultTask, out exception))
            {
                if ((this.Exception = exception) is null)
                {
                    lock (this._lock)
                        this.CurrentState = SocketPipeReaderValueTaskState.ReadOutputPipe;
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

        private bool VerifyOutputReadResult(in ValueTask<ReadResult> readresultValueTask, out Exception exception)
        {
            exception = null;
            try
            {
                lock(this._lock)
                    this.ReadResult = readresultValueTask.Result; //should throw the exception????

                if (readresultValueTask.IsCompletedSuccessfully)
                    return true;
                else if (readresultValueTask.IsFaulted)
                    throw new InvalidOperationException("Reader read operation has failed");
                else if (readresultValueTask.IsCanceled)
                    throw new OperationCanceledException("Reader read has been canceled");

                if (!this.ReadResult.IsCompleted)
                    throw new InvalidOperationException("Reader read has not been completed succesfully");
                if (this.ReadResult.IsCanceled)
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
        #endregion

        public ValueTaskSourceStatus GetStatus(short token)
        {
            if (!(this.Exception is null))
                return ValueTaskSourceStatus.Faulted;

            if (this.CurrentState < SocketPipeReaderValueTaskState.ReadOutputPipe)
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
            this.InvokeContinuation(this.CurrentContinuation, state);
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

        public ReadResult GetResult(short token)
        {
            try
            {
                lock (this._lock)
                {
                    if (!(this.Exception is null))
                        throw new AggregateException(this.Exception);

                    if (EqualityComparer<ReadResult>.Default.Equals(this.ReadResult, default)) //TODO: if there's an excpetion, it gets thrown here
                        throw new InvalidOperationException("Result has not been computed yet");
                }

                return this.ReadResult;
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
                this.CurrentState = SocketPipeReaderValueTaskState.None;
                this.FlushResultTask = default;
                this.ReadResultTask = default;
                this.CancellationToken = default;

                this.ExecutionContext = null;
                this.SynchronizationContext = null;
                this.CurrentContinuation = null;
                this.State = null;
                this.Exception = null;
            }
        }
    }
}
