using System;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
    internal abstract class SafeX509InfoHandle : SafeBaseHandle, IStackable
    {
        private static Func<IntPtr, bool, SafeX509CertificateHandle> createCertificate;

        private SafeX509CertificateHandle x509Certificate;
        public SafeX509CertificateHandle X509Certificate => this.x509Certificate;

        private static Func<IntPtr, bool, SafeX509CertificateHandle> CreateCertificateCreationDelegate()
        {
            Type concretetex509CertificateType = DynamicTypeBuilder.GetConcreteOwnType<SafeX509CertificateHandle>();
            ConstructorInfo ctor = concretetex509CertificateType.GetConstructor(BindingFlags.Public | BindingFlags.Instance, null, new Type[] { typeof(IntPtr), typeof(bool), typeof(bool) }, null);

            ParameterExpression parPtr = Expression.Parameter(typeof(IntPtr));
            ParameterExpression parOwn = Expression.Parameter(typeof(bool));
            Expression constNew = Expression.Constant(true);

            NewExpression create = Expression.New(ctor, parPtr, parOwn, constNew);
            return Expression.Lambda<Func<IntPtr, bool, SafeX509CertificateHandle>>(create, parPtr, parOwn).Compile();
        }

        internal SafeX509InfoHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeX509InfoHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        private SafeX509CertificateHandle GetCertificate(IntPtr ptr)
        {
            if (createCertificate is null)
                createCertificate = CreateCertificateCreationDelegate();

            return createCertificate(ptr, false);
        }

        internal override void PostConstruction()
        {
            X509_INFO raw = Marshal.PtrToStructure<X509_INFO>(this.handle);
            this.x509Certificate = this.GetCertificate(raw.x509);
        }

        protected override bool ReleaseHandle()
        {
            //frees certificate!
            this.CryptoWrapper.X509_INFO_free(this.handle);
            return true;
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
