using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NippyWard.OpenSSL.Interop.SafeHandles.Crypto;

namespace NippyWard.OpenSSL.Keys
{
    public class KeyContext : IDisposable
    {
        internal readonly SafeKeyContextHandle _keyContextHandle;

        internal KeyContext(SafeKeyContextHandle keyContextHandle)
        {
            this._keyContextHandle = keyContextHandle;
        }

        public void Dispose()
        {
            this._keyContextHandle?.Dispose();
        }
    }
}
