using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Buffers;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Keys;
using System.Collections;

namespace OpenSSL.Core.X509
{
    public abstract class X509CertificateBase : OpenSslWrapperBase, IFile
    {
        private X509Name x509name;
        internal X509Name X509Name => x509name ?? (x509name = new X509Name(this.GetSubject()));

        internal PrivateKey PrivateKey { get; private set; }

        private PublicKey publicKey;
        private bool ownsPrivateKey;

        #region Properties

        public string Common
        {
            get => this.X509Name.Common;
            set => this.X509Name.Common = value;
        }

        public string Country
        {
            get => this.X509Name.Country;
            set => this.X509Name.Country = value;
        }

        public string Locality
        {
            get => this.X509Name.Locality;
            set => this.X509Name.Locality = value;
        }

        public string StateOrProvince
        {
            get => this.X509Name.StateOrProvince;
            set => this.X509Name.StateOrProvince = value;
        }

        public string Organization
        {
            get => this.X509Name.Organization;
            set => this.X509Name.Organization = value;
        }

        public string OrganizationUnit
        {
            get => this.X509Name.OrganizationUnit;
            set => this.X509Name.OrganizationUnit = value;
        }

        public string Given
        {
            get => this.X509Name.Given;
            set => this.X509Name.Given = value;
        }

        public string Surname
        {
            get => this.X509Name.Surname;
            set => this.X509Name.Surname = value;
        }

        public string Initials
        {
            get => this.X509Name.Initials;
            set => this.X509Name.Initials = value;
        }

        public string UniqueIdentifier
        {
            get => this.X509Name.UniqueIdentifier;
            set => this.X509Name.UniqueIdentifier = value;
        }

        public string Title
        {
            get => this.X509Name.Title;
            set => this.X509Name.Title = value;
        }

        public string Description
        {
            get => this.X509Name.Description;
            set => this.X509Name.Description = value;
        }

        public abstract int Version { get; set; }
        public PublicKey PublicKey => this.publicKey ?? (this.publicKey = this.GetPublicKey());

        #endregion

        /// <summary>
        /// The actual x509 get assigned after
        /// </summary>
        /// <param name="keyHandle"></param>
        internal X509CertificateBase(SafeKeyHandle keyHandle)
            : this()
        {
            this.PrivateKey = PrivateKey.GetCorrectKey(keyHandle);
            this.ownsPrivateKey = true;
        }

        internal X509CertificateBase()
            : base()
        { }

        public X509CertificateBase(int bits)
            : this()
        {
            //macro functions are version dependant (rsa.h)
            //set up an EVP_PKEY_CTX for RSA key generation
            //SafeKeyContextHandle keyContextHandle;
            //SafeKeyHandle keyHandle = null;

            //using (keyContextHandle = this.CryptoWrapper.EVP_PKEY_CTX_new_id((int)KeyType.RSA, IntPtr.Zero))
            //{
            //    this.CryptoWrapper.EVP_PKEY_keygen_init(keyContextHandle);

            //    //set the bits
            //    this.CryptoWrapper.EVP_PKEY_CTX_set_rsa_keygen_bits(keyContextHandle, bits);

            //    //generate the key
            //    this.CryptoWrapper.EVP_PKEY_keygen(keyContextHandle, out keyHandle);
            //}

            //this.PrivateKey = PrivateKey.GetCorrectKey(keyHandle);

            this.PrivateKey = new RSAKey(1024);
            this.PrivateKey.GenerateKey();

            this.CreateSafeHandle();
            this.SetPublicKey(this.PrivateKey);
            this.ownsPrivateKey = true;
        }

        public X509CertificateBase(PrivateKey privateKey)
            : this()
        {
            this.CreateSafeHandle();
            this.PrivateKey = privateKey;
            this.SetPublicKey(this.PrivateKey);
        }

        #region Methods

        public void Sign(Key key, DigestType digestType)
        {
            SafeMessageDigestHandle md;
            using (md = this.CryptoWrapper.EVP_get_digestbyname(digestType.ShortNamePtr))
            {
                this.Sign(key.KeyWrapper.Handle, md);
            }
        }

        /// <summary>
        /// verifies the signature of a public key
        /// </summary>
        /// <param name="key">The public key to check</param>
        /// <returns></returns>
        public abstract bool VerifyPublicKey(IPublicKey key);

        /// <summary>
        /// Verifies if a private key belongs to this certificate
        /// </summary>
        /// <param name="key">The private key to check</param>
        /// <returns></returns>
        public abstract bool VerifyPrivateKey(PrivateKey key);

        public void Write(string filePath, string password, CipherType cipherType, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            using (FileStream stream = new FileStream(filePath, FileMode.CreateNew))
                this.Write(stream, password, cipherType, fileEncoding);
        }

        public void Write(Stream stream, string password, CipherType cipherType, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            if (!stream.CanWrite)
                throw new InvalidOperationException("Stream is not writable");

            byte[] buf = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                int read;
                using (SafeBioHandle bio = this.CryptoWrapper.BIO_new(this.CryptoWrapper.BIO_s_mem()))
                {
                    this.WriteCertificate(bio, password, cipherType, fileEncoding);
                    Span<byte> bufSpan = new Span<byte>(buf);
                    while ((read = this.CryptoWrapper.BIO_read(bio, ref bufSpan.GetPinnableReference(), bufSpan.Length)) > 0)
                    {
                        stream.Write(buf, 0, read);
                        Array.Clear(buf, 0, read);
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        internal abstract void WriteCertificate(SafeBioHandle bioHandle, string password, CipherType cipherType, FileEncoding fileEncoding);
        #endregion

        #region Abstract method overrides

        internal abstract void CreateSafeHandle();
        internal abstract void SetPublicKey(PrivateKey privateKey);
        internal abstract PublicKey GetPublicKey();

        internal abstract SafeX509NameHandle GetSubject();
        internal abstract void Sign(SafeKeyHandle keyHandle, SafeMessageDigestHandle md);

        #endregion

        protected override void Dispose(bool disposing)
        {
            if (!(this.x509name is null))
                this.x509name.Dispose();

            if (this.ownsPrivateKey && !(this.PrivateKey is null) && !this.PrivateKey.KeyWrapper.Handle.IsInvalid)
                this.PrivateKey.Dispose();
        }
    }
}
