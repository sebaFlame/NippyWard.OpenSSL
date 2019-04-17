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

        internal X509_INFO Raw { get; private set; }

        public SafeX509CertificateHandle X509Certificate
        {
            get
            {
                if (!(this.x509Certificate is null))
                    return this.x509Certificate;

                return (this.x509Certificate = createCertificate(this.Raw.x509, true));
            }
        }

        //TODO: can be called before any call to Native
        static SafeX509InfoHandle()
        {
            Type concretetex509CertificateType = DynamicTypeBuilder.GetConcreteNewType<SafeX509CertificateHandle>();
            ConstructorInfo ctor = concretetex509CertificateType.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(IntPtr), typeof(bool) }, null);

            ParameterExpression parPtr = Expression.Parameter(typeof(IntPtr));
            ParameterExpression parOwn = Expression.Parameter(typeof(bool));

            NewExpression create = Expression.New(ctor, parPtr, parOwn);
            createCertificate = Expression.Lambda<Func<IntPtr, bool, SafeX509CertificateHandle>>(create, parPtr, parOwn).Compile();
        }

        internal SafeX509InfoHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeX509InfoHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        internal override void PostConstruction()
        {
            this.Raw = Marshal.PtrToStructure<X509_INFO>(this.handle);
        }

        protected override bool ReleaseHandle()
        {
            this.CryptoWrapper.X509_INFO_free(this);
            return true;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct X509_INFO : IStackable
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
