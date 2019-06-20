using System;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;

namespace OpenSSL.Core.SSL.Pipelines
{
    internal class SocketPipeWriterAwaitable : IValueTaskSource<SocketFlushResult>
    {
        private PipeAwaitable _writeCompletedAwaitable;

        //changing state
        private long _writtenLength;
        private ValueTask<FlushResult> _flushResultTask;

        internal SocketPipeWriterAwaitable(bool useSynchronizationContext)
        {
            this._writeCompletedAwaitable = new PipeAwaitable(completed: false, useSynchronizationContext);
        }

        internal void Complete(long writtenLength, out CompletionData completionData)
        {
            this._writtenLength = writtenLength;
            this._writeCompletedAwaitable.Complete(out completionData);
            this._writeCompletedAwaitable.Reset();
        }

        internal void Reset(ValueTask<FlushResult> flushResult)
        {
            this._writtenLength = 0;
            this._flushResultTask = flushResult;
            this._writeCompletedAwaitable.Reset();

            //you can assume flush got completed when send completes
            //if (!flushResult.IsCompleted)
            //{
            //    ConfiguredValueTaskAwaitable<FlushResult> task = flushResult.ConfigureAwait(false);
            //    task.GetAwaiter().OnCompleted(this.ContinueFlushAndAwaitSocketCompletion);
            //}
        }

        public SocketFlushResult GetResult(short token)
        {
            SocketFlushResult socketFlushResult = new SocketFlushResult(this._flushResultTask.Result, this._writtenLength);
            return socketFlushResult;
        }

        public ValueTaskSourceStatus GetStatus(short token)
        {
            if (this._flushResultTask.IsCompleted && this._writeCompletedAwaitable.IsCompleted)
                return ValueTaskSourceStatus.Succeeded;

            return ValueTaskSourceStatus.Pending;
        }

        public void OnCompleted(Action<object> continuation, object state, short token, ValueTaskSourceOnCompletedFlags flags)
        {
            this._writeCompletedAwaitable.OnCompleted(continuation, state, flags, out CompletionData completionData, out bool doubleCompletion);
        }
    }
}
