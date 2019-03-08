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

namespace OpenSSL.Core.X509
{
    public class X509CertificateRequest : X509CertificateBase
    {
        internal SafeX509RequestHandle RequestHandle;

        internal X509CertificateRequest(SafeX509RequestHandle requestHandle)
            : base()
        {
            this.RequestHandle = requestHandle;
        }

        //only use for CA?
        internal X509CertificateRequest(SafeX509RequestHandle x509RequestHandle, SafeKeyHandle keyHandle)
            : base(keyHandle)
        {
            this.RequestHandle = x509RequestHandle;
        }

        public X509CertificateRequest(int bits)
            : base(bits)
        { }

        public X509CertificateRequest(int bits, string OU, string CN)
            : this(bits)
        {
            this.OrganizationUnit = OU;
            this.Common = CN;
        }

        public X509CertificateRequest(PrivateKey privateKey)
            : base(privateKey)
        { }

        public X509CertificateRequest(PrivateKey privateKey, string OU, string CN)
            : this(privateKey)
        {
            this.OrganizationUnit = OU;
            this.Common = CN;
        }

        public override int Version
        {
            get => (int)this.CryptoWrapper.X509_REQ_get_version(this.RequestHandle);
            set => this.CryptoWrapper.X509_REQ_set_version(this.RequestHandle, value);
        }

        public override bool VerifyPrivateKey(PrivateKey key)
        {
            return this.CryptoWrapper.X509_REQ_check_private_key(this.RequestHandle, key.KeyHandle) == 1;
        }

        public override bool VerifyPublicKey(IPublicKey key)
        {
            return this.CryptoWrapper.X509_REQ_verify(this.RequestHandle, ((Key)key).KeyHandle) == 1;
        }

        internal override void CreateSafeHandle()
        {
            this.RequestHandle = this.CryptoWrapper.X509_REQ_new();
        }

        internal override PublicKey GetPublicKey()
        {
            return new PublicKey(this.CryptoWrapper.X509_REQ_get_pubkey(this.RequestHandle));
        }

        internal override SafeX509NameHandle GetSubject()
        {
            return this.CryptoWrapper.X509_REQ_get_subject_name(this.RequestHandle);
        }

        internal override void SetPublicKey(PrivateKey privateKey)
        {
            this.CryptoWrapper.X509_REQ_set_pubkey(this.RequestHandle, privateKey.KeyHandle);
        }

        internal override void Sign(SafeKeyHandle keyHandle, SafeMessageDigestHandle md)
        {
            this.CryptoWrapper.X509_REQ_sign(this.RequestHandle, keyHandle, md);
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
            if (this.RequestHandle is null || this.RequestHandle.IsInvalid)
                throw new InvalidOperationException("Key has not been genrated yet");

            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            if (fileEncoding == FileEncoding.PEM)
                this.CryptoWrapper.PEM_write_bio_X509_REQ(bioHandle, this.RequestHandle);
            else if (fileEncoding == FileEncoding.DER)
                this.CryptoWrapper.i2d_X509_REQ_bio(bioHandle, this.RequestHandle);
            else
                throw new FormatException("Encoding not supported");
        }

        public override void Dispose()
        {
            if (!(this.RequestHandle is null) && !this.RequestHandle.IsInvalid)
                this.RequestHandle.Dispose();

            base.Dispose();
        }
    }
}
