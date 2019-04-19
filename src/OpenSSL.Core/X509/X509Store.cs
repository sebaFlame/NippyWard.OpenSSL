using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

using OpenSSL.Core.Error;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Collections;

namespace OpenSSL.Core.X509
{
    public class X509Store : OpenSslWrapperBase
    {
        internal class X509StoreInternal : SafeHandleWrapper<SafeX509StoreHandle>
        {
            internal X509StoreInternal(SafeX509StoreHandle safeHandle)
                : base(safeHandle) { }
        }

        internal X509StoreInternal StoreWrapper { get; private set; }
        internal override ISafeHandleWrapper HandleWrapper => this.StoreWrapper;

        public X509Store()
            : base()
        {
            this.StoreWrapper = new X509StoreInternal(this.CryptoWrapper.X509_STORE_new());
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
                this.StoreWrapper.Handle,
                caFileSpan.GetPinnableReference(),
                certPathSpan.GetPinnableReference());
        }

        internal X509Store(SafeX509StoreHandle storeHandle)
            : base()
        {
            this.StoreWrapper = new X509StoreInternal(storeHandle);
        }

        internal X509Store(SafeStackHandle<SafeX509CertificateHandle> stackHandle)
            : this()
        {
            foreach (SafeX509CertificateHandle cert in stackHandle)
                this.CryptoWrapper.X509_STORE_add_cert(this.StoreWrapper.Handle, cert);
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

        public void AddCertificate(X509Certificate certificate)
        {
            this.CryptoWrapper.X509_STORE_add_cert(this.StoreWrapper.Handle, certificate.X509Wrapper.Handle);
        }

        public OpenSslReadOnlyCollection<X509Certificate> GetCertificates()
        {
            SafeStackHandle<SafeX509ObjectHandle> safeObjHandle = this.CryptoWrapper.X509_STORE_get0_objects(this.StoreWrapper.Handle);
            SafeStackHandle<SafeX509CertificateHandle> safeCertHandle = this.CryptoWrapper.OPENSSL_sk_new_null<SafeX509CertificateHandle>();

            SafeX509CertificateHandle certificate;
            foreach (SafeX509ObjectHandle obj in safeObjHandle)
            {
                if (!((certificate = this.CryptoWrapper.X509_OBJECT_get0_X509(obj)) is null))
                    safeCertHandle.Add(certificate);
            }

            return OpenSslReadOnlyCollection<X509Certificate>.CreateFromSafeHandle(safeCertHandle);
        }

        /// <summary>
        /// Verify validity of a certificate using this store
        /// </summary>
        /// <param name="cert">The certificate to check</param>
        /// <param name="extraChain">Extra certificates not available int the current store</param>
        /// <returns></returns>
        public bool Verify(X509Certificate cert, out VerifyResult verifyResult, OpenSslEnumerable<X509Certificate> extraChain = null)
        {
            using (SafeX509StoreContextHandle ctx = this.CryptoWrapper.X509_STORE_CTX_new())
            {
                this.CryptoWrapper.X509_STORE_CTX_init(
                    ctx, 
                    this.StoreWrapper.Handle, 
                    cert.X509Wrapper.Handle, 
                    extraChain is null ? null : (SafeStackHandle<SafeX509CertificateHandle>)extraChain.InternalEnumerable.Handle);
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

        protected override void Dispose(bool disposing)
        {
            //NOP
        }
    }
}
