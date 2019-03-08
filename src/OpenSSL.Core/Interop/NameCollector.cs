using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace OpenSSL.Core.Interop
{
    internal class NameCollector
    {
        [StructLayout(LayoutKind.Sequential)]
        struct OBJ_NAME
        {
            public int type;
            public int alias;
            public IntPtr name;
            public IntPtr data;
        };

        public HashSet<string> Result { get; private set; }

        public NameCollector(int type, bool isSorted)
        {
            this.Result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (isSorted)
                Native.CryptoWrapper.OBJ_NAME_do_all_sorted(type, OnObjectName, IntPtr.Zero);
            else
                Native.CryptoWrapper.OBJ_NAME_do_all(type, OnObjectName, IntPtr.Zero);
        }

        private void OnObjectName(IntPtr ptr, IntPtr arg)
        {
            var name = Marshal.PtrToStructure<OBJ_NAME>(ptr);
            var str = Native.PtrToStringAnsi(name.name, false);
            this.Result.Add(str);
        }
    }
}
