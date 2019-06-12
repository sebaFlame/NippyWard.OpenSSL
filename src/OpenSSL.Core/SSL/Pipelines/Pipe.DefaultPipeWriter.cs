// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;

namespace OpenSSL.Core.SSL.Pipelines
{
    /// <summary>
    /// Default <see cref="PipeWriter"/> and <see cref="PipeReader"/> implementation.
    /// </summary>
    public abstract partial class Pipe
    {
        private sealed class DefaultPipeWriter : PipeWriter, IValueTaskSource<FlushResult>
        {
            private readonly Pipe _pipe;

            public DefaultPipeWriter(Pipe pipe)
            {
                _pipe = pipe;
            }

            public override void Complete(Exception exception = null) => _pipe.CompleteWriter(exception);

            public override void CancelPendingFlush() => _pipe.CancelPendingFlush();

            public override void OnReaderCompleted(Action<Exception, object> callback, object state) => _pipe.OnReaderCompleted(callback, state);

            public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default) => _pipe.FlushAsync(cancellationToken);

            public override void Advance(int bytes) => _pipe.Advance(bytes);

            public override Memory<byte> GetMemory(int sizeHint = 0) => _pipe.GetMemory(sizeHint);

            public override Span<byte> GetSpan(int sizeHint = 0) => _pipe.GetMemory(sizeHint).Span;

            public ValueTaskSourceStatus GetStatus(short token) => _pipe.GetFlushAsyncStatus();

            public FlushResult GetResult(short token) => _pipe.GetFlushAsyncResult();

            public void OnCompleted(Action<object> continuation, object state, short token, ValueTaskSourceOnCompletedFlags flags) => _pipe.OnFlushAsyncCompleted(continuation, state, flags);
        }

        private sealed class DefaultInterruptedPipeWriter : IValueTaskSource<FlushResult>
        {
            private readonly Pipe _pipe;

            public DefaultInterruptedPipeWriter(Pipe pipe)
            {
                _pipe = pipe;
            }

            public ValueTaskSourceStatus GetStatus(short token) => _pipe.GetFlushAsyncStatus();
            public FlushResult GetResult(short token) => _pipe.GetFlushAsyncResult();
            public void OnCompleted(Action<object> continuation, object state, short token, ValueTaskSourceOnCompletedFlags flags) => _pipe.OnFlushAsyncCompleted(continuation, state, flags);
        }
    }
}
