using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

using NippyWard.OpenSSL.Interop.Wrappers;

namespace NippyWard.OpenSSL.Interop
{
    /// <summary>
    ///
    /// </summary>
    public enum MemoryProblemType
	{
		/// <summary>
		///
		/// </summary>
		Leaked,
		/// <summary>
		///
		/// </summary>
		MultipleFree,
	}

	/// <summary>
	///
	/// </summary>
	public class MemoryProblem
	{
		/// <summary>
		///
		/// </summary>
		public MemoryProblemType Type { get; set; }
		/// <summary>
		///
		/// </summary>
		public uint Size { get; set; }
		/// <summary>
		///
		/// </summary>
		public int FreeCount { get; set; }
		/// <summary>
		///
		/// </summary>
		public StackTrace? StackTrace { get; set; }
		/// <summary>
		///
		/// </summary>
		public string? File { get; set; }
		/// <summary>
		///
		/// </summary>
		public int Line { get; set; }

        internal IntPtr Ptr { get; set; }

		/// <summary>
		///
		/// </summary>
		/// <returns></returns>
		public override string ToString()
		{
			return string.Format($"{this.Type}: {this.Size} bytes, {this.FreeCount} count, {this.File!}:{this.Line}\n{this.StackTrace!.ToString()}");
		}
	}

	/// <summary>
	/// Useful for tracking down memory leaks
	/// </summary>
	internal class MemoryTracker
	{
		private class Block
		{
			public string? file;
			public int line;
			public StackTrace? stack;
			public uint bytes;
			public IntPtr ptr;
			public bool skip;
			public int count;

			public override string ToString()
			{
				return string.Format("{0}{1}: {2} bytes at {3}:{4}", skip ? "*" : " ", count, bytes, file, line);
			}
		}

		// These are used to pin the functions down so they don't get yanked while in use
		static MallocFunctionPtr _PtrMalloc = malloc;
		static ReallocFunctionPtr _PtrRealloc = realloc;
		static FreeFunctionPtr _PtrFree = free;

		static bool _Tracking = false;
		static Dictionary<IntPtr, Block> _Memory = new Dictionary<IntPtr, Block>();
        static bool _Initialized;

		/// <summary>
		/// Initialize memory routines
		/// </summary>
		public static void Init()
		{
            Native.CryptoWrapper.CRYPTO_set_mem_functions(_PtrMalloc, _PtrRealloc, _PtrFree);
            _Initialized = true;
		}

		/// <summary>
		/// Begins memory tracking
		/// </summary>
		public static void Start()
		{
            if (!_Initialized)
                return;

			lock (_Memory)
			{
				_Tracking = true;
				foreach (var item in _Memory)
				{
					item.Value.skip = true;
				}
			}
		}

		/// <summary>
		/// Stops memory tracking and reports any leaks found since Start() was called.
		/// </summary>
		public static List<MemoryProblem> Finish()
		{
            if (!_Initialized)
                return Enumerable.Empty<MemoryProblem>().ToList();

            GC.Collect();
			GC.WaitForPendingFinalizers();
			GC.Collect();

			_Tracking = false;

			return Flush();
		}

		static List<MemoryProblem> Flush()
		{
			var problems = new List<MemoryProblem>();

			lock (_Memory)
			{
				var frees = new List<Block>();

				foreach (var item in _Memory)
				{
					var block = item.Value;
					if (block.skip)
						continue;

					if (block.count == 0)
						block.skip = true;

					if (block.count > 0)
						frees.Add(block);

					if (block.count == 0 || block.count > 1)
					{
						var problem = new MemoryProblem
						{
							Type = block.count == 0 ? MemoryProblemType.Leaked : MemoryProblemType.MultipleFree,
							Size = block.bytes,
							FreeCount = block.count,
							StackTrace = block.stack,
							File = block.file,
							Line = block.line,
                            Ptr = block.ptr
						};
						Debug.WriteLine(problem.ToString());
						problems.Add(problem);
					}
				}

				foreach (var block in frees)
				{
					Marshal.FreeHGlobal(block.ptr);
					_Memory.Remove(block.ptr);
				}
			}

			return problems;
		}

		static IntPtr malloc(nuint num, IntPtr file, int line)
		{
			lock (_Memory)
			{
                var block = new Block
                {
                    file = Native.PtrToStringAnsi(file, false),
                    line = line,
                    stack = new StackTrace(true),
                    bytes = (uint)num,
                    ptr = Marshal.AllocHGlobal((int)num),
                    count = _Tracking ? 0 : 1
				};
				_Memory.Add(block.ptr, block);
				return block.ptr;
			}
		}

        static IntPtr free(IntPtr addr, IntPtr file, int line)
		{
			lock (_Memory)
			{
				Block? block;
				if (!_Memory.TryGetValue(addr, out block))
					return addr;

                if (_Tracking)
				{
					block.count++;
				}
				else
				{
					Marshal.FreeHGlobal(addr);
					_Memory.Remove(addr);
				}

                return block.ptr;
			}
		}

		static IntPtr realloc(IntPtr addr, nuint num, IntPtr file, int line)
		{
			lock (_Memory)
			{
				if (!_Memory.Remove(addr))
					return malloc(num, file, line);

				var block = new Block
				{
					stack = new StackTrace(true),
					file = Native.PtrToStringAnsi(file, false),
					line = line,
					bytes = (uint)num,
					ptr = Marshal.ReAllocHGlobal(addr, (IntPtr)((int)num)),
                    count = _Tracking ? 0 : 1
                };

				_Memory.Add(block.ptr, block);
				return block.ptr;
			}
		}
	}
}
