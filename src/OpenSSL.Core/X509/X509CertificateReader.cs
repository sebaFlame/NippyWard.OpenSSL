using System;
using System.Buffers;
using System.IO;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Collections;

namespace OpenSSL.Core.X509
{
    public class X509CertificateReader : IDisposable
    {
        private SafeBioHandle currentBioHandle;
        public OpenSslList<X509Certificate> Certificates { get; private set; }

        /// <summary>
        /// Read from a stream concatenated PEM formatted CA file
        /// Like the one from https://curl.haxx.se/ca/cacert.pem
        /// </summary>
        /// <param name="stream">The stream to read the file from</param>
        public X509CertificateReader(Stream stream)
        {
            this.currentBioHandle = this.Initialize(stream);
            this.Certificates = this.ProcessBio(this.currentBioHandle);
        }

        /// <summary>
        /// Read a file with certificates in PEM format
        /// </summary>
        /// <param name="file">The file to read</param>
        public X509CertificateReader(FileInfo file)
        {
            this.Initialize(file.OpenRead());
            this.Certificates = this.ProcessBio(this.currentBioHandle);
        }

        internal X509CertificateReader(SafeBioHandle bio)
        {
            Native.CryptoWrapper.BIO_up_ref(bio);
            this.Certificates = this.ProcessBio(this.currentBioHandle);
        }

        /// <summary>
        /// Read a directory with certificates in PEM format
        /// </summary>
        /// <param name="dir"></param>
        public X509CertificateReader(DirectoryInfo dir)
        {
            this.Certificates = this.ProcessDir(dir);
        }

        private SafeBioHandle Initialize(Stream stream)
        {
            SafeBioHandle bio = Native.CryptoWrapper.BIO_new(Native.CryptoWrapper.BIO_s_mem());

            int read = 0;
            byte[] buf = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                Span<byte> bufSpan = new Span<byte>(buf);
                while ((read = stream.Read(buf, 0, buf.Length)) > 0)
                {
                    Native.CryptoWrapper.BIO_write(this.currentBioHandle, bufSpan.GetPinnableReference(), read);
                    Array.Clear(buf, 0, read);
                }

                return bio;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        private OpenSslList<X509Certificate> ProcessBio(SafeBioHandle currentBio)
        {
            SafeStackHandle<SafeX509InfoHandle> currentInfoStack = Native.CryptoWrapper.PEM_X509_INFO_read_bio(currentBio, null, null, IntPtr.Zero);
            SafeStackHandle<SafeX509CertificateHandle> certificates = Native.CryptoWrapper.OPENSSL_sk_new_null<SafeX509CertificateHandle>();

            SafeX509CertificateHandle certificate;
            foreach(SafeX509InfoHandle info in currentInfoStack)
            {
                certificate = info.X509Certificate;
                if (certificate is null)
                    continue;
                certificates.Add(certificate);
            }

            return OpenSslList<X509Certificate>.CreateFromSafeHandle(certificates);
        }

        //TODO: add exception handling
        private OpenSslList<X509Certificate> ProcessDir(DirectoryInfo dir)
        {
            SafeStackHandle<SafeX509CertificateHandle> certificates = Native.CryptoWrapper.OPENSSL_sk_new_null<SafeX509CertificateHandle>();
            this.GetCertificates(dir, certificates);
            return OpenSslList<X509Certificate>.CreateFromSafeHandle(certificates);
        }

        private void GetCertificates(DirectoryInfo dir, SafeStackHandle<SafeX509CertificateHandle> certificates)
        {
            foreach (FileInfo file in dir.GetFiles())
                certificates.Add(readCertificate(file));

            foreach (DirectoryInfo d in dir.GetDirectories())
                this.GetCertificates(d, certificates);
        }

        private SafeX509CertificateHandle readCertificate(FileInfo file)
        {
            int read = 0;
            byte[] buf = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                using(FileStream stream = file.OpenRead())
                {
                    using (SafeBioHandle bio = Native.CryptoWrapper.BIO_new(Native.CryptoWrapper.BIO_s_mem()))
                    {
                        Span<byte> bufSpan = new Span<byte>(buf);
                        while ((read = stream.Read(buf, 0, buf.Length)) > 0)
                        {
                            Native.CryptoWrapper.BIO_write(bio, bufSpan.GetPinnableReference(), read);
                            Array.Clear(buf, 0, read);
                        }

                        return Native.CryptoWrapper.PEM_read_bio_X509(bio, IntPtr.Zero, null, IntPtr.Zero);
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        public void Dispose()
        {
            if (!(this.currentBioHandle is null) && !this.currentBioHandle.IsInvalid)
                this.currentBioHandle.Dispose();
        }
    }
}
