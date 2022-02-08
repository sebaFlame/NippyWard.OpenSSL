using System;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
    internal abstract class SafeX509InfoHandle : BaseValue, IStackable
    {
        public SafeX509CertificateHandle X509Certificate { get; private set; }

        internal SafeX509InfoHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeX509InfoHandle(IntPtr ptr, bool takeOwnership, bool isNew)
            : base(ptr, takeOwnership, isNew)
        { }

        private SafeX509CertificateHandle GetCertificate(IntPtr ptr)
            => SafeHandleFactory.CreateReferenceSafeHandle<SafeX509CertificateHandle>(ptr);

        internal override void PostConstruction()
        {
            X509_INFO raw = Marshal.PtrToStructure<X509_INFO>(this.handle);
            this.X509Certificate = this.GetCertificate(raw.x509);
        }

        protected override bool ReleaseHandle()
        {
            //frees certificate!
            CryptoWrapper.X509_INFO_free(this.handle);
            return true;
        }

        //does not get called
        internal override IntPtr Duplicate()
        {
            throw new NotImplementedException();
        }
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
