﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSSL.Core.SSL
{
#if DEBUG
#pragma warning disable CS1591
    public static class DebugCounters
    {
        public static void Reset() => Helpers.ResetCounters();
        public static string GetSummary() => Helpers.GetCounterSummary();

        public static void SetLog(System.IO.TextWriter log) => Helpers.Log = log ?? System.IO.TextWriter.Null;
    }
#pragma warning restore CS1591
#endif

    internal enum Counter
    {
        SocketGetBufferList,

        SocketSendAsyncSingleSync,
        SocketSendAsyncSingleAsync,
        SocketSendAsyncMultiSync,
        SocketSendAsyncMultiAsync,

        SocketPipeReadReadSync,
        SocketPipeReadReadAsync,
        SocketPipeFlushSync,
        SocketPipeFlushAsync,

        SocketReceiveSync,
        SocketReceiveAsync,
        SocketZeroLengthReceiveSync,
        SocketZeroLengthReceiveAsync,
        SocketSendAsyncSync,
        SocketSendAsyncAsync,

        SocketAwaitableCallbackNone,
        SocketAwaitableCallbackDirect,
        SocketAwaitableCallbackSchedule,

        ThreadPoolWorkerStarted,
        ThreadPoolPushedToMainThreadPool,
        ThreadPoolScheduled,
        ThreadPoolExecuted,

        PipeStreamWrite,
        PipeStreamWriteAsync,
        PipeStreamWriteByte,
        PipeStreamBeginWrite,
        PipeStreamWriteSpan,
        PipeStreamWriteAsyncMemory,

        PipeStreamRead,
        PipeStreamReadAsync,
        PipeStreamReadByte,
        PipeStreamBeginRead,
        PipeStreamReadSpan,
        PipeStreamReadAsyncMemory,

        PipeStreamFlush,
        PipeStreamFlushAsync,

        OpenReceiveReadAsync,
        OpenReceiveFlushAsync,
        OpenSendReadAsync,
        OpenSendWriteAsync,
        SocketConnectionCollectedWithoutDispose,
    }
    internal static class Helpers
    {
#if DEBUG
        private readonly static int[] _counters = new int[Enum.GetValues(typeof(Counter)).Length];
        internal static void ResetCounters()
        {
            Array.Clear(_counters, 0, _counters.Length);
            lock(_execCount) { _execCount.Clear(); }
        }
        internal static string GetCounterSummary()
        {
            var enums = (Counter[])Enum.GetValues(typeof(Counter));
            var sb = new System.Text.StringBuilder();
            for(int i = 0 ; i < enums.Length ; i++)
            {
                var count = Thread.VolatileRead(ref _counters[(int)enums[i]]);
                if (count != 0) sb.AppendLine($"{enums[i]}:\t{count}");
            }
            lock(_execCount)
            {
                foreach(var pair in _execCount)
                {
                    sb.AppendLine($"{pair.Key}:\t{pair.Value}");
                }
            }
            return sb.ToString();
        }
        static readonly Dictionary<string, int> _execCount = new Dictionary<string, int>();
#endif
        [Conditional("DEBUG")]
#pragma warning disable RCS1163 // Unused parameter.
        internal static void Incr(Counter counter)
#pragma warning restore RCS1163 // Unused parameter.
        {
#if DEBUG
            Interlocked.Increment(ref _counters[(int)counter]);
#endif
        }
        [Conditional("DEBUG")]
#pragma warning disable RCS1163 // Unused parameter.
        internal static void Decr(Counter counter)
#pragma warning restore RCS1163 // Unused parameter.
        {
#if DEBUG
            Interlocked.Decrement(ref _counters[(int)counter]);
#endif
        }
        [Conditional("DEBUG")]
#pragma warning disable RCS1163 // Unused parameter.
        internal static void Incr(MethodInfo method)
#pragma warning restore RCS1163 // Unused parameter.
        {
#if DEBUG
            lock(_execCount)
            {
                var name = $"{method.DeclaringType.FullName}.{method.Name}";
                if (!_execCount.TryGetValue(name, out var count)) count = 0;
                _execCount[name] = count + 1;
            }
#endif
        }

        private static string s_assemblyFailureMessssage = null;
        private static string GetAssemblyFailureMessage()
        {
            string ComputeAssemblyFailureMessage()
            {
                bool havePipe = false, haveBuffers = false;
                try { CheckPipe(); havePipe = true; } catch { }
                try { CheckBuffers(); haveBuffers = true; } catch { }

                if (havePipe && haveBuffers) return "";

                var missing = havePipe ? "System.Buffers" : (haveBuffers ? "System.IO.Pipelines" : "System.Buffers and System.IO.Pipelines");
                return "The assembly for " + missing + " could not be loaded; this usually means a missing assembly binding redirect - try checking this, and adding any that are missing;"
                    + " note that it is not always possible to add this redirects - for example 'azure functions v1'; it looks like you may need to use 'azure functions v2' for that - sorry, but that's out of our control";
        }
            return s_assemblyFailureMessssage ?? (s_assemblyFailureMessssage = ComputeAssemblyFailureMessage());
        }
        internal static void AssertDependencies()
        {
            void Throw(string msg) => throw new InvalidOperationException(msg);
            string err = GetAssemblyFailureMessage();
            if (!string.IsNullOrEmpty(err)) Throw(err);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void CheckPipe() => GC.KeepAlive(typeof(System.IO.Pipelines.Pipe));

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void CheckBuffers() => GC.KeepAlive(typeof(System.Buffers.ArrayPool<byte>));

#pragma warning disable RCS1231 // Make parameter ref read-only.
        internal static ArraySegment<byte> GetArray(this Memory<byte> buffer) => GetArray((ReadOnlyMemory<byte>)buffer);
        internal static ArraySegment<byte> GetArray(this ReadOnlyMemory<byte> buffer)
#pragma warning restore RCS1231 // Make parameter ref read-only.
        {
            if (!MemoryMarshal.TryGetArray<byte>(buffer, out var segment)) throw new InvalidOperationException("MemoryMarshal.TryGetArray<byte> could not provide an array");
            return segment;
        }

#if DEBUG
        internal static System.IO.TextWriter Log = System.IO.TextWriter.Null;
#endif

        [Conditional("VERBOSE")]
#pragma warning disable RCS1163 // Unused parameter.
        internal static void DebugLog(string name, string message, [CallerMemberName] string caller = null)
#pragma warning restore RCS1163 // Unused parameter.
        {
#if VERBOSE
            
            var log = Log;
            if (log != null)
            {
                var thread = System.Threading.Thread.CurrentThread;
                var threadName = thread.Name;
                if (string.IsNullOrWhiteSpace(threadName)) threadName = thread.ManagedThreadId.ToString();
                    
                var s = $"[{threadName}, {name}, {caller}]: {message}";
                lock (log)
                {
                    try { log.WriteLine(s); }
                    catch { }
                }
            }
#endif
        }

        internal static void PipelinesFireAndForget(this Task task)
            => task?.ContinueWith(t => GC.KeepAlive(t.Exception), TaskContinuationOptions.OnlyOnFaulted);
    }
}
