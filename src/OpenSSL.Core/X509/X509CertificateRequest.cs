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
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.X509
{
    [Wrapper(typeof(X509CertificateRequestInternal))]
    public class X509CertificateRequest : X509CertificateBase
    {
        internal class X509CertificateRequestInternal : SafeHandleWrapper<SafeX509RequestHandle>
        {
            internal X509CertificateRequestInternal(SafeX509RequestHandle safeHandle)
                : base(safeHandle) { }
        }

        internal X509CertificateRequestInternal X509RequestWrapper { get; private set; }
        internal override ISafeHandleWrapper HandleWrapper => this.X509RequestWrapper;

        internal X509CertificateRequest(X509CertificateRequestInternal handleWrapper)
            : base()
        {
            this.X509RequestWrapper = handleWrapper;
        }

        internal X509CertificateRequest(SafeX509RequestHandle requestHandle)
            : base()
        {
            this.X509RequestWrapper = new X509CertificateRequestInternal(requestHandle);
        }

        //only use for CA?
        internal X509CertificateRequest(SafeX509RequestHandle x509RequestHandle, SafeKeyHandle keyHandle)
            : base(keyHandle)
        {
            this.X509RequestWrapper = new X509CertificateRequestInternal(x509RequestHandle);
        }

        public X509CertificateRequest(int bits)
            : base(bits)
        {
            this.Version = 2;
        }

        public X509CertificateRequest(int bits, string OU, string CN)
            : this(bits)
        {
            this.OrganizationUnit = OU;
            this.Common = CN;
        }

        public X509CertificateRequest(PrivateKey privateKey)
            : base(privateKey)
        {
            this.Version = 2;
        }

        public X509CertificateRequest(PrivateKey privateKey, string OU, string CN)
            : this(privateKey)
        {
            this.OrganizationUnit = OU;
            this.Common = CN;
        }

        public override int Version
        {
            get => (int)this.CryptoWrapper.X509_REQ_get_version(this.X509RequestWrapper.Handle);
            set => this.CryptoWrapper.X509_REQ_set_version(this.X509RequestWrapper.Handle, value);
        }

        public override bool VerifyPrivateKey(PrivateKey key)
        {
            return this.CryptoWrapper.X509_REQ_check_private_key(this.X509RequestWrapper.Handle, key.KeyWrapper.Handle) == 1;
        }

        public override bool VerifyPublicKey(IPublicKey key)
        {
            return this.CryptoWrapper.X509_REQ_verify(this.X509RequestWrapper.Handle, ((Key)key).KeyWrapper.Handle) == 1;
        }

        internal override void CreateSafeHandle()
        {
            this.X509RequestWrapper = new X509CertificateRequestInternal(this.CryptoWrapper.X509_REQ_new());
        }

        internal override PublicKey GetPublicKey()
        {
            return new PublicKey(this.CryptoWrapper.X509_REQ_get_pubkey(this.X509RequestWrapper.Handle));
        }

        internal override SafeX509NameHandle GetSubject()
        {
            return this.CryptoWrapper.X509_REQ_get_subject_name(this.X509RequestWrapper.Handle);
        }

        internal override void SetPublicKey(PrivateKey privateKey)
        {
            this.CryptoWrapper.X509_REQ_set_pubkey(this.X509RequestWrapper.Handle, privateKey.KeyWrapper.Handle);
        }

        internal override void Sign(SafeKeyHandle keyHandle, SafeMessageDigestHandle md)
        {
            this.CryptoWrapper.X509_REQ_sign(this.X509RequestWrapper.Handle, keyHandle, md);
        }

        public static X509CertificateRequest Read(string filePath, string password, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"The file {filePath} has not been found");

            ReadOnlySpan<char> strPath = Path.GetFullPath(filePath).AsSpan();
            ReadOnlySpan<byte> readonlySpan = new Span<byte>(Native.ReadOnly);

            using (FileStream stream = new FileStream(filePath, FileMode.Open))
                return Read(stream, password, fileEncoding);
        }

        public static X509CertificateRequest Read(Stream stream, string password, FileEncoding fileEncoding = FileEncoding.PEM)
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

        internal static X509CertificateRequest ReadCertificate(SafeBioHandle bioHandle, string password, FileEncoding fileEncoding)
        {
            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            if (fileEncoding == FileEncoding.PEM)
                return new X509CertificateRequest(Native.CryptoWrapper.PEM_read_bio_X509_REQ(bioHandle, IntPtr.Zero, pass.Callback, IntPtr.Zero));
            else if (fileEncoding == FileEncoding.DER)
                return new X509CertificateRequest(Native.CryptoWrapper.d2i_X509_REQ_bio(bioHandle, IntPtr.Zero));

            throw new FormatException("Encoding not supported");
        }

        internal override void WriteCertificate(SafeBioHandle bioHandle, string password, CipherType cipherType, FileEncoding fileEncoding)
        {
            if (this.X509RequestWrapper.Handle is null || this.X509RequestWrapper.Handle.IsInvalid)
                throw new InvalidOperationException("Key has not been genrated yet");

            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            if (fileEncoding == FileEncoding.PEM)
                this.CryptoWrapper.PEM_write_bio_X509_REQ(bioHandle, this.X509RequestWrapper.Handle);
            else if (fileEncoding == FileEncoding.DER)
                this.CryptoWrapper.i2d_X509_REQ_bio(bioHandle, this.X509RequestWrapper.Handle);
            else
                throw new FormatException("Encoding not supported");
        }
    }
}
