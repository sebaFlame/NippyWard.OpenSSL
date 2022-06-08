using System;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
    internal abstract class SafeX509InfoHandle : BaseValue, IStackable
    {
        public static SafeX509InfoHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeX509InfoHandle>(IntPtr.Zero);

        //frees certificate!
        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static readonly OPENSSL_sk_freefunc _FreeFunc;

        static SafeX509InfoHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.X509_INFO_free);
        }

        public SafeX509CertificateHandle X509Certificate
        {
            get
            {
                X509_INFO raw = Marshal.PtrToStructure<X509_INFO>(this.handle);
                return SafeHandleFactory.CreateWrapperSafeHandle<SafeX509CertificateHandle>(raw.x509);
            }
        }

        internal SafeX509InfoHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeX509InfoHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct X509_INFO
    {
        public IntPtr x509;
        public IntPtr crl;
        public IntPtr x_pkey;
        #region EVP_CIPHER_INFO enc_cipher;
        public IntPtr cipher;
        public fixed byte iv[Native.EVP_MAX_IV_LENGTH];
        #endregion
        public int enc_len;
        public IntPtr enc_data;
        public int references;
    }
}
