using System;
using System.Collections.Generic;
using System.IO;
using System.Buffers;
using System.Text;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Keys;
using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop.Wrappers;
using System.Collections;

namespace OpenSSL.Core.X509
{
    [Wrapper(typeof(X509CertificateInternal))]
    public class X509Certificate : X509CertificateBase, IEquatable<X509Certificate>, IEnumerable<X509Extension>
    {
        internal class X509CertificateInternal : SafeHandleWrapper<SafeX509CertificateHandle>
        {
            internal X509CertificateInternal(SafeX509CertificateHandle safeHandle)
                : base(safeHandle) { }
        }

        internal X509CertificateInternal X509Wrapper { get; private set; }
        internal override ISafeHandleWrapper HandleWrapper => this.X509Wrapper;

        #region Properties

        public DateTime NotBefore
        {
            get => CryptoWrapper.X509_get0_notBefore(this.X509Wrapper.Handle).DateTime;
            set
            {
                SafeAsn1DateTimeHandle timeHandle, timeHandleDup;
                using (timeHandle = CryptoWrapper.ASN1_TIME_new())
                {
                    using (timeHandleDup = CryptoWrapper.ASN1_TIME_set(timeHandle, SafeAsn1DateTimeHandle.DateTimeToTimeT(value)))
                        CryptoWrapper.X509_set1_notBefore(this.X509Wrapper.Handle, timeHandleDup);
                }
            }
        }

        public DateTime NotAfter
        {
            get => CryptoWrapper.X509_get0_notAfter(this.X509Wrapper.Handle).DateTime;
            set
            {
                SafeAsn1DateTimeHandle timeHandle, timeHandleDup;
                using (timeHandle = CryptoWrapper.ASN1_TIME_new())
                {
                    using (timeHandleDup = CryptoWrapper.ASN1_TIME_set(timeHandle, SafeAsn1DateTimeHandle.DateTimeToTimeT(value)))
                        CryptoWrapper.X509_set1_notAfter(this.X509Wrapper.Handle, timeHandle);
                }
            }
        }

        public int SerialNumber
        {
            get
            {
                SafeAsn1IntegerHandle integer;
                using (integer = CryptoWrapper.X509_get_serialNumber(this.X509Wrapper.Handle))
                    return integer.Value;
            }
            set
            {
                SafeAsn1IntegerHandle integer;
                using (integer = CryptoWrapper.ASN1_INTEGER_new())
                {
                    integer.Value = value;
                    CryptoWrapper.X509_set_serialNumber(this.X509Wrapper.Handle, integer);
                }
            }
        }

        public override int Version
        {
            get => (int)CryptoWrapper.X509_get_version(this.X509Wrapper.Handle);
            set => CryptoWrapper.X509_set_version(this.X509Wrapper.Handle, value);
        }

        #endregion

        #region Constructors

        internal X509Certificate(X509CertificateInternal handleWrapper)
            : base()
        {
            this.X509Wrapper = handleWrapper;
        }

        internal X509Certificate(SafeX509CertificateHandle x509Handle)
            : base()
        {
            this.X509Wrapper = new X509CertificateInternal(x509Handle);
        }

        //only use for CA?
        internal X509Certificate(SafeX509CertificateHandle x509Handle, SafeKeyHandle keyHandle)
            : this(x509Handle)
        {
            this.SetPublicKey(PrivateKey.GetCorrectKey(keyHandle));
        }

        public X509Certificate(int bits)
            : base(bits)
        {
            this.Version = 2;
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
            this.Version = 2;
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

                    //dispose of possible unnecessary handles
                    if(ca.IsInvalid)
                    {
                        ca.Dispose();
                    }

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
            if (this.X509Wrapper.Handle is null || this.X509Wrapper.Handle.IsInvalid)
                throw new InvalidOperationException("Key has not been genrated yet");

            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            if (fileEncoding == FileEncoding.PEM)
                CryptoWrapper.PEM_write_bio_X509(bioHandle, this.X509Wrapper.Handle);
            else if (fileEncoding == FileEncoding.DER)
                CryptoWrapper.i2d_X509_bio(bioHandle, this.X509Wrapper.Handle);
            else if (fileEncoding == FileEncoding.PKCS12)
            {
                //TODO: cipherType incorrect? should be a PBE?
                SafePKCS12Handle pkcs12Handle = CryptoWrapper.PKCS12_create(password, "", this.PublicKey?.KeyWrapper.Handle, this.X509Wrapper.Handle, null, cipherType.NID, 0, 2048, 1, 0);
                CryptoWrapper.i2d_PKCS12_bio(bioHandle, pkcs12Handle);
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
            using (md = CryptoWrapper.EVP_get_digestbyname(digestType.ShortNamePtr))
            {
                CryptoWrapper.X509_sign(this.X509Wrapper.Handle, this.PublicKey.KeyWrapper.Handle, md);
                CryptoWrapper.X509_set_issuer_name(this.X509Wrapper.Handle, this.X509Name.X509NameWrapper.Handle);
            }
        }

        internal void SetIssuer(X509Name x509Name)
        {
            CryptoWrapper.X509_set_issuer_name(this.X509Wrapper.Handle, x509Name.X509NameWrapper.Handle);
        }

        #region X509Extension
        internal void AddExtension(SafeX509ExtensionHandle extensionHandle)
        {
            CryptoWrapper.X509_add_ext(this.X509Wrapper.Handle, extensionHandle, -1);
        }

        public void AddX509Extension(X509ExtensionType type, string value)
        {
            this.AddExtension(null, type, value);
        }

        internal void AddExtension(
            X509Certificate issuer,
            X509CertificateRequest request,
            X509ExtensionType type, 
            string internalValue)
        {
            using (SafeX509ExtensionContextHandle ctx = new SafeX509ExtensionContextHandle())
            {
                CryptoWrapper.X509V3_set_ctx(
                    ctx,
                    issuer is null ? IntPtr.Zero : issuer.X509Wrapper.Handle.DangerousGetHandle(),
                    this.X509Wrapper.Handle.DangerousGetHandle(),
                    request is null ? IntPtr.Zero : request.X509RequestWrapper.Handle.DangerousGetHandle(),
                    IntPtr.Zero,
                    0);

                this.AddExtension(ctx, type, internalValue);
            }
        }

        internal void AddExtension(
            SafeX509ExtensionContextHandle ctx,
            X509ExtensionType type,
            string internalValue)
        {
            SafeX509ExtensionHandle extension;
            unsafe
            {
                ReadOnlySpan<char> span = internalValue.AsSpan();
                fixed (char* c = span)
                {
                    int length = Encoding.ASCII.GetEncoder().GetByteCount(c, span.Length, false);
                    byte* b = stackalloc byte[length + 1];
                    Encoding.ASCII.GetEncoder().GetBytes(c, span.Length, b, length, true);
                    Span<byte> buf = new Span<byte>(b, length + 1);
                    if (ctx is null)
                        extension = CryptoWrapper.X509V3_EXT_conf_nid(IntPtr.Zero, IntPtr.Zero, type.NID, buf.GetPinnableReference());
                    else
                        extension = CryptoWrapper.X509V3_EXT_conf_nid(IntPtr.Zero, ctx, type.NID, buf.GetPinnableReference());
                }
            }

            this.AddExtension(extension);
        }

        public IEnumerator<X509Extension> GetEnumerator()
        {
            return new X509ExtensionEnumerator(CryptoWrapper, this.X509Wrapper.Handle);
        }

        IEnumerator IEnumerable.GetEnumerator() => this.GetEnumerator();
        #endregion

        #region abstract overrides

        internal override void CreateSafeHandle()
        {
            this.X509Wrapper = new X509CertificateInternal(CryptoWrapper.X509_new());
        }

        internal override void SetPublicKey(PrivateKey privateKey)
        {
            //adds a reference on the key!!!
            CryptoWrapper.X509_set_pubkey(this.X509Wrapper.Handle, privateKey.KeyWrapper.Handle);
        }

        internal override PrivateKey GetPublicKey()
        {
            return PrivateKey.GetCorrectKey(CryptoWrapper.X509_get0_pubkey(this.X509Wrapper.Handle));
        }

        public override bool VerifyPublicKey(IPublicKey key)
        {
            try
            {
                return CryptoWrapper.X509_verify(this.X509Wrapper.Handle, ((Key)key).KeyWrapper.Handle) == 1;
            }
            finally
            {
                CryptoWrapper.ERR_clear_error();
            }
        }

        public override bool VerifyPrivateKey(PrivateKey key)
        {
            try
            {
                return CryptoWrapper.X509_check_private_key(this.X509Wrapper.Handle, key.KeyWrapper.Handle) == 1;
            }
            finally
            {
                CryptoWrapper.ERR_clear_error();
            }
        }

        internal override SafeX509NameHandle GetSubject()
        {
            return CryptoWrapper.X509_get_subject_name(this.X509Wrapper.Handle);
        }

        internal override void Sign(SafeKeyHandle key, SafeMessageDigestHandle md)
        {
            CryptoWrapper.X509_sign(this.X509Wrapper.Handle, key, md);
        }

        #endregion

        public bool Equals(X509Certificate other)
        {
            if (other.X509Wrapper.Handle is null || other.X509Wrapper.Handle.IsInvalid)
                throw new InvalidOperationException("Certificate hasn't been generated yet");

            if (this.X509Wrapper.Handle is null || this.X509Wrapper.Handle.IsInvalid)
                throw new InvalidOperationException("Certificate hasn't been generated yet");

            return CryptoWrapper.X509_cmp(this.X509Wrapper.Handle, other.X509Wrapper.Handle) == 0;
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
            {
                return this.hashCode;
            }

            IntPtr algorithm = new IntPtr();

            CryptoWrapper.X509_get0_signature(out SafeASN1BitStringHandle stringHandle, algorithm, this.X509Wrapper.Handle);
            Span<byte> sig = stringHandle.Value;
            this.hashCode = sig.GetHashCode();

            return this.hashCode;
        }

        private struct X509ExtensionEnumerator : IEnumerator<X509Extension>
        {
            private ILibCryptoWrapper CryptoWrapper;
            private SafeX509CertificateHandle CertHandle;
            private int position;

            public X509Extension Current => new X509Extension(CryptoWrapper.X509_get_ext(this.CertHandle, this.position));
            object IEnumerator.Current => this.Current;

            internal X509ExtensionEnumerator(
                ILibCryptoWrapper cryptoWrapper,
                SafeX509CertificateHandle certHandle)
            {
                CryptoWrapper = cryptoWrapper;
                this.CertHandle = certHandle;
                this.position = -1;
            }

            public bool MoveNext()
            {
                return ++position < CryptoWrapper.X509_get_ext_count(this.CertHandle);
            }

            public void Reset()
            {
                this.position = -1;
            }

            public void Dispose()
            {

            }
        }
    }
}
