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
using System.Collections;

namespace OpenSSL.Core.X509
{
    public class X509Store
        : OpenSslWrapperBase,
            ISafeHandleWrapper<SafeX509StoreHandle>
    {
        SafeX509StoreHandle ISafeHandleWrapper<SafeX509StoreHandle>.Handle
            => this._Handle;
        public override SafeHandle Handle
            => this._Handle;

        internal readonly SafeX509StoreHandle _Handle;

        private X509Store()
            : base()
        {
            this._Handle = CryptoWrapper.X509_STORE_new();
        }

        public X509Store(FileInfo CAFile)
            : this(CAFile, null) { }

        public X509Store(DirectoryInfo certPath)
            : this(null, certPath) { }

        public X509Store(FileInfo? CAFile, DirectoryInfo? certPath)
            : this()
        {
            ReadOnlySpan<byte> caFileSpan = default, certPathSpan = default;

            if(!(CAFile is null))
                caFileSpan = GetCorrectPath(CAFile.FullName);
            
            if(!(certPath is null))
                certPathSpan = GetCorrectPath(certPath.FullName);

            if(!(CAFile is null) && !(certPath is null))
                CryptoWrapper.X509_STORE_load_locations(
                    this._Handle,
                    caFileSpan.GetPinnableReference(),
                    certPathSpan.GetPinnableReference());
            else if(!(CAFile is null))
                CryptoWrapper.X509_STORE_load_locations(
                    this._Handle,
                    caFileSpan.GetPinnableReference(),
                    IntPtr.Zero);
            else if(!(certPath is null))
                CryptoWrapper.X509_STORE_load_locations(
                    this._Handle,
                    IntPtr.Zero,
                    certPathSpan.GetPinnableReference());
        }

        internal X509Store(SafeX509StoreHandle storeHandle)
            : base()
        {
            this._Handle = storeHandle;
        }

        public X509Store(IEnumerable<X509Certificate> caList)
            : this()
        {
            foreach (X509Certificate cert in caList)
            {
                CryptoWrapper.X509_STORE_add_cert
                (
                    this._Handle,
                    cert._Handle
                );;
            }
        }

        internal X509Store(SafeStackHandle<SafeX509CertificateHandle> stackHandle)
            : this()
        {
            foreach (SafeX509CertificateHandle cert in stackHandle)
            {
                CryptoWrapper.X509_STORE_add_cert(this._Handle, cert);
            }
        }

        private static ReadOnlySpan<byte> GetCorrectPath(string fullName)
        {
            byte[] b = Encoding.UTF8.GetBytes(fullName);
            return new ReadOnlySpan<byte>(b);
        }

        public void AddCertificate(X509Certificate certificate)
        {
            CryptoWrapper.X509_STORE_add_cert(this._Handle, certificate._Handle);
        }

        public IOpenSslReadOnlyCollection<X509Certificate> GetCertificates()
        {
            SafeStackHandle<SafeX509ObjectHandle> safeObjHandle = CryptoWrapper.X509_STORE_get0_objects(this._Handle);
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

            return new OpenSslList<X509Certificate, SafeX509CertificateHandle>(safeCertHandle);
        }

        /// <summary>
        /// Verify validity of a certificate using this store
        /// </summary>
        /// <param name="cert">The certificate to check</param>
        /// <param name="extraChain">Extra certificates not available int the current store</param>
        /// <returns></returns>
        public bool Verify
        (
            X509Certificate cert,
            out VerifyResult verifyResult,
            IOpenSslReadOnlyCollection<X509Certificate>? extraChain = null
        )
        {
            OpenSslList<X509Certificate, SafeX509CertificateHandle>? extra = null;
            if(extraChain is not null)
            {
                if(!(extraChain is OpenSslList<X509Certificate, SafeX509CertificateHandle>))
                {
                    throw new InvalidOperationException($"{nameof(extraChain)} is in an incorrect format. Please construct using this library.");
                }
                extra = (OpenSslList<X509Certificate, SafeX509CertificateHandle>)extraChain;
            }

            using (SafeX509StoreContextHandle ctx = CryptoWrapper.X509_STORE_CTX_new())
            {
                CryptoWrapper.X509_STORE_CTX_init
                (
                    ctx,
                    this._Handle,
                    cert._Handle,
                    extra is null
                        ? SafeStackHandle<SafeX509CertificateHandle>.Zero
                        : extra._Handle
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
