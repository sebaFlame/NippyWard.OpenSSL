using System;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
    internal class SafeX509ExtensionContextHandle : SafeBaseHandle
    {
        internal SafeX509ExtensionContextHandle()
            : base(true)
        {
            unsafe
            {
                ReadOnlySpan<char> span = Assembly.GetEntryAssembly().FullName.AsSpan();

                fixed (char* c = span)
                {
                    int bufLength = Encoding.ASCII.GetEncoder().GetByteCount(c, span.Length, false);
                    byte* b = stackalloc byte[bufLength + 1];
                    Encoding.ASCII.GetEncoder().GetBytes(c, span.Length, b, bufLength, true);
                    Span<byte> buf = new Span<byte>(b, bufLength + 1);
                    this.SetHandle(CryptoWrapper.CRYPTO_malloc((ulong)Marshal.SizeOf<X509V3_CTX>(), buf.GetPinnableReference(), 0));
                }
            }
        }

        protected override bool ReleaseHandle()
        {
            Native.Free(this.handle);
            return true;
        }

        #region X509V3_CTX
        [StructLayout(LayoutKind.Sequential)]
        internal struct X509V3_CTX
        {
            public int flags;
            public IntPtr issuer_cert;
            public IntPtr subject_cert;
            public IntPtr subject_req;
            public IntPtr crl;
            public IntPtr db_meth;
            public IntPtr db;
        }
        #endregion
    }
}
