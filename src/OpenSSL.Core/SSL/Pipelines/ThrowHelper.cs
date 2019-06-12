// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;

namespace OpenSSL.Core.SSL.Pipelines
{
    internal static class ThrowHelper
    {
        internal static void ThrowArgumentOutOfRangeException(ExceptionArgument argument) => throw CreateArgumentOutOfRangeException(argument);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentOutOfRangeException(ExceptionArgument argument) => new ArgumentOutOfRangeException(argument.ToString());

        internal static void ThrowArgumentNullException(ExceptionArgument argument) => throw CreateArgumentNullException(argument);
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Exception CreateArgumentNullException(ExceptionArgument argument) => new ArgumentNullException(argument.ToString());

        public static void ThrowInvalidOperationException_NotWritingNoAlloc() { throw CreateInvalidOperationException_NotWritingNoAlloc(); }
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_NotWritingNoAlloc() => new InvalidOperationException("No writing operation. Make sure GetMemory() was called.");

        public static void ThrowInvalidOperationException_AlreadyReading() => throw CreateInvalidOperationException_AlreadyReading();
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_AlreadyReading() => new InvalidOperationException("Reading is already in progress.");

        public static void ThrowInvalidOperationException_NoReadToComplete() => throw CreateInvalidOperationException_NoReadToComplete();
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_NoReadToComplete() => new InvalidOperationException("No reading operation to complete.");

        public static void ThrowInvalidOperationException_NoConcurrentOperation() => throw CreateInvalidOperationException_NoConcurrentOperation();
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_NoConcurrentOperation() => new InvalidOperationException("Concurrent reads or writes are not supported.");

        public static void ThrowInvalidOperationException_GetResultNotCompleted() => throw CreateInvalidOperationException_GetResultNotCompleted();
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_GetResultNotCompleted() => new InvalidOperationException("Can't GetResult unless awaiter is completed.");

        public static void ThrowInvalidOperationException_NoWritingAllowed() => throw CreateInvalidOperationException_NoWritingAllowed();

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_NoWritingAllowed() => new InvalidOperationException("Writing is not allowed after writer was completed.");

        public static void ThrowInvalidOperationException_NoReadingAllowed() => throw CreateInvalidOperationException_NoReadingAllowed();
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_NoReadingAllowed() => new InvalidOperationException("Reading is not allowed after reader was completed.");

        public static void ThrowInvalidOperationException_AdvancingPastBufferSize() => throw CreateInvalidOperationException_AdvancingPastBufferSize();
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_AdvancingPastBufferSize() => new InvalidOperationException("Can't advance past buffer size.");

        public static void ThrowInvalidOperationException_BackpressureDeadlock() => throw CreateInvalidOperationException_BackpressureDeadlock();
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_BackpressureDeadlock() => new InvalidOperationException("Advancing examined to the end would cause pipe to deadlock because FlushAsync is waiting.");

        public static void ThrowInvalidOperationException_AdvanceToInvalidCursor() => throw CreateInvalidOperationException_AdvanceToInvalidCursor();
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_AdvanceToInvalidCursor() => new InvalidOperationException("Pipe is already advanced past provided cursor.");

        public static void ThrowInvalidOperationException_ResetIncompleteReaderWriter() => throw CreateInvalidOperationException_ResetIncompleteReaderWriter();
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception CreateInvalidOperationException_ResetIncompleteReaderWriter() => new InvalidOperationException("Both reader and writer has to be completed to be able to reset the pipe.");
    }

    internal enum ExceptionArgument
    {
        minimumSize,
        bytesWritten,
        callback,
        options,
        pauseWriterThreshold,
        resumeWriterThreshold
    }
}
