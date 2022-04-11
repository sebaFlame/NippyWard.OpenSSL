using System;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
    internal abstract class SafeX509ExtensionContextHandle : SafeBaseHandle
    {
        public static SafeX509ExtensionContextHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeX509ExtensionContextHandle>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => Native._FreeMallocFunc;

        internal SafeX509ExtensionContextHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeX509ExtensionContextHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        internal static SafeX509ExtensionContextHandle CreateInstance()
        {
            IntPtr ptr;

            unsafe
            {
                ReadOnlySpan<char> span = Assembly.GetEntryAssembly().FullName.AsSpan();

                fixed (char* c = span)
                {
                    int bufLength = Encoding.ASCII.GetEncoder().GetByteCount(c, span.Length, false);
                    byte* b = stackalloc byte[bufLength + 1];
                    Encoding.ASCII.GetEncoder().GetBytes(c, span.Length, b, bufLength, true);
                    Span<byte> buf = new Span<byte>(b, bufLength + 1);
                    ptr = CryptoWrapper.CRYPTO_malloc((ulong)Marshal.SizeOf<X509V3_CTX>(), buf.GetPinnableReference(), 0);
                }
            }

            return Native.SafeHandleFactory.CreateTakeOwnershipSafeHandle<SafeX509ExtensionContextHandle>(ptr);
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
