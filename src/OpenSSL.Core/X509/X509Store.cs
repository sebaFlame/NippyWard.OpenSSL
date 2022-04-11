using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

using OpenSSL.Core.Error;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Collections;

using OpenSSL.Core.Interop;
using System.Reflection;

namespace OpenSSL.Core.X509
{
    [Wrapper(typeof(X509StoreInternal))]
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
            this.StoreWrapper = new X509StoreInternal(CryptoWrapper.X509_STORE_new());
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

            if(!(CAFile is null) && !(certPath is null))
                CryptoWrapper.X509_STORE_load_locations(
                    this.StoreWrapper.Handle,
                    caFileSpan.GetPinnableReference(),
                    certPathSpan.GetPinnableReference());
            else if(!(CAFile is null))
                CryptoWrapper.X509_STORE_load_locations(
                    this.StoreWrapper.Handle,
                    caFileSpan.GetPinnableReference(),
                    IntPtr.Zero);
            else if(!(certPath is null))
                CryptoWrapper.X509_STORE_load_locations(
                    this.StoreWrapper.Handle,
                    IntPtr.Zero,
                    certPathSpan.GetPinnableReference());
        }

        internal X509Store(X509StoreInternal handleWrapper)
            : base()
        {
            this.StoreWrapper = handleWrapper;
        }

        internal X509Store(SafeX509StoreHandle storeHandle)
            : base()
        {
            this.StoreWrapper = new X509StoreInternal(storeHandle);
        }

        public X509Store(IEnumerable<X509Certificate> caList)
            : this()
        {
            foreach (X509Certificate cert in caList)
            {
                CryptoWrapper.X509_STORE_add_cert(this.StoreWrapper.Handle, cert.X509Wrapper.Handle);
            }
        }

        internal X509Store(SafeStackHandle<SafeX509CertificateHandle> stackHandle)
            : this()
        {
            foreach (SafeX509CertificateHandle cert in stackHandle)
            {
                CryptoWrapper.X509_STORE_add_cert(this.StoreWrapper.Handle, cert);
            }
        }

        private static ReadOnlySpan<byte> GetCorrectPath(string fullName)
        {
            byte[] b = Encoding.UTF8.GetBytes(fullName);
            return new ReadOnlySpan<byte>(b);
        }

        public void AddCertificate(X509Certificate certificate)
        {
            CryptoWrapper.X509_STORE_add_cert(this.StoreWrapper.Handle, certificate.X509Wrapper.Handle);
        }

        public OpenSslReadOnlyCollection<X509Certificate> GetCertificates()
        {
            SafeStackHandle<SafeX509ObjectHandle> safeObjHandle = CryptoWrapper.X509_STORE_get0_objects(this.StoreWrapper.Handle);
            SafeStackHandle<SafeX509CertificateHandle> safeCertHandle = StackWrapper.OPENSSL_sk_new_null<SafeX509CertificateHandle>();

            SafeX509CertificateHandle certificate;
            foreach (SafeX509ObjectHandle obj in safeObjHandle)
            {
                if (!((certificate = CryptoWrapper.X509_OBJECT_get0_X509(obj)) is null))
                {
                    certificate.AddReference();
                    safeCertHandle.Add(certificate);
                }
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
            using (SafeX509StoreContextHandle ctx = CryptoWrapper.X509_STORE_CTX_new())
            {
                CryptoWrapper.X509_STORE_CTX_init
                (
                    ctx,
                    this.StoreWrapper.Handle,
                    cert.X509Wrapper.Handle,
                    extraChain is null
                        ? SafeStackHandle<SafeX509CertificateHandle>.Zero
                        : (SafeStackHandle<SafeX509CertificateHandle>)extraChain.InternalEnumerable.Handle
                );
                try
                {
                    return CryptoWrapper.X509_verify_cert(ctx) == 1;
                }
                finally
                {
                    if ((verifyResult = (VerifyResult)CryptoWrapper.X509_STORE_CTX_get_error(ctx)) != VerifyResult.X509_V_OK)
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
