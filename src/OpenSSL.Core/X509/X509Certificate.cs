using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Buffers;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Interop.Wrappers;
using OpenSSL.Core.Keys;
using OpenSSL.Core.ASN1;
using System.Collections;

namespace OpenSSL.Core.X509
{
    public class X509Certificate : X509CertificateBase, IEquatable<X509Certificate>
    {
        private X509ExtensionEnumerator x509ExtensionEnumerator;

        internal SafeX509CertificateHandle X509Handle;

        public ICollection<X509Extension> X509Extensions => this.x509ExtensionEnumerator;

        #region Properties

        public DateTime NotBefore
        {
            get => this.CryptoWrapper.X509_get0_notBefore(this.X509Handle).DateTime;
            set
            {
                SafeAsn1DateTimeHandle timeHandle, timeHandleDup;
                using (timeHandle = this.CryptoWrapper.ASN1_TIME_new())
                {
                    using (timeHandleDup = this.CryptoWrapper.ASN1_TIME_set(timeHandle, SafeAsn1DateTimeHandle.DateTimeToTimeT(value)))
                        this.CryptoWrapper.X509_set1_notBefore(this.X509Handle, timeHandleDup);
                }
            }
        }

        public DateTime NotAfter
        {
            get => this.CryptoWrapper.X509_get0_notAfter(this.X509Handle).DateTime;
            set
            {
                SafeAsn1DateTimeHandle timeHandle, timeHandleDup;
                using (timeHandle = this.CryptoWrapper.ASN1_TIME_new())
                {
                    using (timeHandleDup = this.CryptoWrapper.ASN1_TIME_set(timeHandle, SafeAsn1DateTimeHandle.DateTimeToTimeT(value)))
                        this.CryptoWrapper.X509_set1_notAfter(this.X509Handle, timeHandle);
                }
            }
        }

        public int SerialNumber
        {
            get
            {
                SafeAsn1IntegerHandle integer;
                using (integer = this.CryptoWrapper.X509_get_serialNumber(this.X509Handle))
                    return integer.Value;
            }
            set
            {
                SafeAsn1IntegerHandle integer;
                using (integer = this.CryptoWrapper.ASN1_INTEGER_new())
                {
                    integer.Value = value;
                    this.CryptoWrapper.X509_set_serialNumber(this.X509Handle, integer);
                }
            }
        }

        public override int Version
        {
            get => (int)this.CryptoWrapper.X509_get_version(this.X509Handle);
            set => this.CryptoWrapper.X509_set_version(this.X509Handle, value);
        }

        #endregion

        #region Constructors

        internal X509Certificate(SafeX509CertificateHandle x509Handle)
            : base()
        {
            this.X509Handle = x509Handle;
            this.GuaranteeEnumerator();
        }

        //only use for CA?
        internal X509Certificate(SafeX509CertificateHandle x509Handle, SafeKeyHandle keyHandle)
            : base(keyHandle)
        {
            this.X509Handle = x509Handle;
            this.GuaranteeEnumerator();
        }

        public X509Certificate(int bits)
            : base(bits)
        {
            this.GuaranteeEnumerator();
        }

        public X509Certificate(int bits, string OU, string CN, DateTime notBefore, DateTime notAfter)
            : this(bits)
        {
            this.OrganizationUnit = OU;
            this.Common = CN;
            this.NotBefore = notBefore;
            this.NotAfter = notAfter;
        }

        public X509Certificate(PrivateKey privateKey)
            : base(privateKey)
        {
            this.GuaranteeEnumerator();
        }

        public X509Certificate(PrivateKey privateKey, string OU, string CN, DateTime notBefore, DateTime notAfter)
            : this(privateKey)
        {
            this.OrganizationUnit = OU;
            this.Common = CN;
            this.NotAfter = notAfter;
            this.NotBefore = notBefore;
        }

        #endregion

        #region IO

        public static X509Certificate Read(string filePath, string password, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"The file {filePath} has not been found");

            ReadOnlySpan<char> strPath = Path.GetFullPath(filePath).AsSpan();
            ReadOnlySpan<byte> readonlySpan = new Span<byte>(Native.ReadOnly);

            using (FileStream stream = new FileStream(filePath, FileMode.Open))
                return Read(stream, password, fileEncoding);
        }

        public static X509Certificate Read(Stream stream, string password, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            if (!stream.CanRead)
                throw new InvalidOperationException("Stream is not readable");

            byte[] buf = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                int read;
                using (SafeBioHandle bio = Native.CryptoWrapper.BIO_new(Native.CryptoWrapper.BIO_s_mem()))
                {
                    Span<byte> bufSpan = new Span<byte>(buf);
                    while ((read = stream.Read(buf, 0, buf.Length)) > 0)
                    {
                        Native.CryptoWrapper.BIO_write(bio, bufSpan.GetPinnableReference(), read);
                        Array.Clear(buf, 0, read);
                    }

                    return ReadCertificate(bio, password, fileEncoding);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        internal static X509Certificate ReadCertificate(SafeBioHandle bioHandle, string password, FileEncoding fileEncoding)
        {
            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            if (fileEncoding == FileEncoding.PEM)
                return new X509Certificate(Native.CryptoWrapper.PEM_read_bio_X509(bioHandle, IntPtr.Zero, pass.Callback, IntPtr.Zero));
            else if (fileEncoding == FileEncoding.DER)
                return new X509Certificate(Native.CryptoWrapper.d2i_X509_bio(bioHandle, IntPtr.Zero));
            else if (fileEncoding == FileEncoding.PKCS12)
            {
                //load the PKCS12 file
                SafePKCS12Handle pkcs12Handle = Native.CryptoWrapper.d2i_PKCS12_bio(bioHandle, IntPtr.Zero);

                try
                {
                    //parse the PKCS12 file
                    Native.CryptoWrapper.PKCS12_parse(pkcs12Handle,
                        password,
                        out SafeKeyHandle pkey,
                        out SafeX509CertificateHandle cert,
                        out SafeStackHandle<SafeX509CertificateHandle>  ca);

                    //dispose of unnecessary handles
                    ca.Dispose();

                    return new X509Certificate(cert, pkey);
                }
                finally
                {
                    pkcs12Handle.Dispose();
                }
            }

            throw new FormatException("Encoding not supported");
        }

        internal override void WriteCertificate(SafeBioHandle bioHandle, string password, CipherType cipherType, FileEncoding fileEncoding)
        {
            if (this.X509Handle is null || this.X509Handle.IsInvalid)
                throw new InvalidOperationException("Key has not been genrated yet");

            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            if (fileEncoding == FileEncoding.PEM)
                this.CryptoWrapper.PEM_write_bio_X509(bioHandle, this.X509Handle);
            else if (fileEncoding == FileEncoding.DER)
                this.CryptoWrapper.i2d_X509_bio(bioHandle, this.X509Handle);
            else if (fileEncoding == FileEncoding.PKCS12)
            {
                //TODO: cipherType incorrect? should be a PBE?
                SafePKCS12Handle pkcs12Handle = this.CryptoWrapper.PKCS12_create(password, "", this.PrivateKey?.KeyHandle, this.X509Handle, null, cipherType.NID, 0, 2048, 1, 0);
                this.CryptoWrapper.i2d_PKCS12_bio(bioHandle, pkcs12Handle);
            }
            else
                throw new FormatException("Encoding not supported");
        }

        #endregion

        public void SelfSign(PrivateKey privateKey, DigestType digestType)
        {
            if (!this.VerifyPrivateKey(privateKey))
                throw new InvalidOperationException("Private and public key do not match");

            SafeMessageDigestHandle md;
            using (md = this.CryptoWrapper.EVP_get_digestbyname(digestType.ShortNamePtr))
            {
                this.CryptoWrapper.X509_sign(this.X509Handle, this.PrivateKey.KeyHandle, md);
                this.CryptoWrapper.X509_set_issuer_name(this.X509Handle, this.X509Name.NameHandle);
            }
        }

        public void AddX509Extension(X509ExtensionType type, bool critical, string value)
        {
            SafeX509ExtensionHandle extensionHandle;
            using (extensionHandle = X509Extension.CreateHandle(type, critical, value))
            {
                this.AddExtension(extensionHandle);
            }
        }

        internal void SetIssuer(X509Name x509Name)
        {
            this.CryptoWrapper.X509_set_issuer_name(this.X509Handle, x509Name.NameHandle);
        }

        internal SafeX509ExtensionHandle GetExtension(int index)
        {
            return this.CryptoWrapper.X509_get_ext(this.X509Handle, index);
        }

        internal int GetMaxExtensionCount()
        {
            return this.CryptoWrapper.X509_get_ext_count(this.X509Handle);
        }

        internal void AddExtension(SafeX509ExtensionHandle extensionHandle)
        {
            this.CryptoWrapper.X509_add_ext(this.X509Handle, extensionHandle, -1);
        }

        private void GuaranteeEnumerator()
        {
            if (!(this.x509ExtensionEnumerator is null))
                return;

            this.x509ExtensionEnumerator = new X509ExtensionEnumerator(this.CryptoWrapper, this.GetExtension, this.GetMaxExtensionCount, this.AddExtension);
        }

        #region abstract overrides

        internal override void CreateSafeHandle()
        {
            this.X509Handle = this.CryptoWrapper.X509_new();
        }

        internal override void SetPublicKey(PrivateKey privateKey)
        {
            this.CryptoWrapper.X509_set_pubkey(this.X509Handle, privateKey.KeyHandle);
        }

        internal override PublicKey GetPublicKey()
        {
            return new PublicKey(this.CryptoWrapper.X509_get_pubkey(this.X509Handle));
        }

        public override bool VerifyPublicKey(IPublicKey key)
        {
            try
            {
                return this.CryptoWrapper.X509_verify(this.X509Handle, ((Key)key).KeyHandle) == 1;
            }
            finally
            {
                this.CryptoWrapper.ERR_clear_error();
            }
        }

        public override bool VerifyPrivateKey(PrivateKey key)
        {
            try
            {
                return this.CryptoWrapper.X509_check_private_key(this.X509Handle, key.KeyHandle) == 1;
            }
            finally
            {
                this.CryptoWrapper.ERR_clear_error();
            }
        }

        internal override SafeX509NameHandle GetSubject()
        {
            return this.CryptoWrapper.X509_get_subject_name(this.X509Handle);
        }

        internal override void Sign(SafeKeyHandle key, SafeMessageDigestHandle md)
        {
            this.CryptoWrapper.X509_sign(this.X509Handle, key, md);
        }

        #endregion

        public bool Equals(X509Certificate other)
        {
            if (other.X509Handle is null || other.X509Handle.IsInvalid)
                throw new InvalidOperationException("Certificate hasn't been generated yet");

            if (this.X509Handle is null || this.X509Handle.IsInvalid)
                throw new InvalidOperationException("Certificate hasn't been generated yet");

            return this.CryptoWrapper.X509_cmp(this.X509Handle, other.X509Handle) == 0;
        }

        public override bool Equals(object obj)
        {
            if (!(obj is X509Certificate other))
                return false;

            return this.Equals(other);
        }

        int hashCode;
        public override int GetHashCode()
        {
            if (this.hashCode > 0)
                return this.hashCode;

            SafeASN1BitStringHandle stringHandle;
            IntPtr algorithm = new IntPtr();
            using (stringHandle = this.CryptoWrapper.ASN1_BIT_STRING_new())
            {
                this.CryptoWrapper.X509_get0_signature(out stringHandle, algorithm, this.X509Handle);
                Span<byte> sig = stringHandle.Value;
                this.hashCode = sig.GetHashCode();
            }

            return this.hashCode;
        }

        public override void Dispose()
        {
            if (!(this.X509Handle is null) && !this.X509Handle.IsInvalid)
                this.X509Handle.Dispose();

            if (this.x509ExtensionEnumerator != null)
                this.x509ExtensionEnumerator.Dispose();

            base.Dispose();
        }
    }
}
