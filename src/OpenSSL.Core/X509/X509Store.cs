using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

using OpenSSL.Core.Error;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;

namespace OpenSSL.Core.X509
{
    public class X509Store : Base
    {
        internal SafeX509StoreHandle StoreHandle { get; private set; }

        public X509Store()
            : base()
        {
            this.StoreHandle = this.CryptoWrapper.X509_STORE_new();
        }

        public X509Store(FileInfo CAFile)
            : this(CAFile, null) { }

        public X509Store(DirectoryInfo certPath)
            : this(null, certPath) { }

        public X509Store(FileInfo CAFile, DirectoryInfo certPath)
            : this()
        {
            ReadOnlySpan<byte> caFileSpan = default, certPathSpan = default;

            if(!(CAFile is null))
                caFileSpan = GetCorrectPath(CAFile.FullName);
            
            if(!(certPath is null))
                certPathSpan = GetCorrectPath(certPath.FullName);

            this.CryptoWrapper.X509_STORE_load_locations(
                this.StoreHandle,
                caFileSpan.GetPinnableReference(),
                certPathSpan.GetPinnableReference());
        }

        private static ReadOnlySpan<byte> GetCorrectPath(string fullName)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return MemoryMarshal.AsBytes(fullName.AsSpan());
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                byte[] b = Encoding.UTF8.GetBytes(fullName);
                return new ReadOnlySpan<byte>(b);
            }

            throw new NotSupportedException("Unknown OS detected");
        }

        internal X509Store(SafeX509StoreHandle storeHandle)
            : base()
        {
            this.StoreHandle = storeHandle;
        }

        internal X509Store(SafeStackHandle<SafeX509CertificateHandle> stackHandle)
            : this()
        {
            foreach (SafeX509CertificateHandle cert in stackHandle)
                this.CryptoWrapper.X509_STORE_add_cert(this.StoreHandle, cert);
        }

        public void AddCertificate(X509Certificate certificate)
        {
            this.CryptoWrapper.X509_STORE_add_cert(this.StoreHandle, certificate.X509Handle);
        }

        public X509CertificateList GetCertificates()
        {
            return new X509CertificateList(this.StoreHandle);
        }

        /// <summary>
        /// Verify validity of a certificate using this store
        /// </summary>
        /// <param name="cert">The certificate to check</param>
        /// <param name="extraChain">Extra certificates not available int the current store</param>
        /// <returns></returns>
        public bool Verify(X509Certificate cert, out VerifyResult verifyResult, X509CertificateList extraChain = null)
        {
            using (SafeX509StoreContextHandle ctx = this.CryptoWrapper.X509_STORE_CTX_new())
            {
                this.CryptoWrapper.X509_STORE_CTX_init(ctx, this.StoreHandle, cert.X509Handle, extraChain is null ? null : extraChain.X509StackHandle);
                try
                {
                    return this.CryptoWrapper.X509_verify_cert(ctx) == 1;
                }
                finally
                {
                    if ((verifyResult = (VerifyResult)this.CryptoWrapper.X509_STORE_CTX_get_error(ctx)) != VerifyResult.X509_V_OK)
                        throw new OpenSslException(new VerifyError(verifyResult));
                }
            }
        }

        public override void Dispose()
        {
            if (!(this.StoreHandle is null) && !this.StoreHandle.IsInvalid)
                this.StoreHandle.Dispose();
        }
    }
}
