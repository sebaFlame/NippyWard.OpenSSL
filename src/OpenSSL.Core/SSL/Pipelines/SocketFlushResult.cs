using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.SSL.Pipelines
{
    internal struct SocketFlushResult
    {
        internal FlushResult _flushResult;
        internal ResultFlags _resultFlags;

        internal SocketFlushResult(FlushResult flushResult, long written)
        {
            _flushResult = flushResult;
            _resultFlags = ResultFlags.None;
            Written = written;
        }

        internal SocketFlushResult(FlushResult flushResult, long written, bool isCanceled, bool isCompleted)
            : this(flushResult, written)
        {
            if (isCanceled)
            {
                _resultFlags |= ResultFlags.Canceled;
            }

            if (isCompleted)
            {
                _resultFlags |= ResultFlags.Completed;
            }
        }

        public bool IsCanceled => _flushResult.IsCanceled || (_resultFlags & ResultFlags.Canceled) != 0;

        public bool IsCompleted => _flushResult.IsCompleted && (_resultFlags & ResultFlags.Completed) != 0;

        internal long Written;
    }
}
