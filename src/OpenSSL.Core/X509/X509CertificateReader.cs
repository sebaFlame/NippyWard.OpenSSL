using System;
using System.Buffers;
using System.IO;
using System.Collections.Generic;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Collections;

namespace OpenSSL.Core.X509
{
    public static class X509CertificateReader
    {
        /// <summary>
        /// Read from a stream concatenated PEM formatted CA file
        /// Like the one from https://curl.haxx.se/ca/cacert.pem
        /// </summary>
        /// <param name="stream">The stream to read the file from</param>
        public static OpenSslList<X509Certificate> ImportPEM(Stream stream)
        {
            using (SafeBioHandle bio = Initialize(stream))
            {
                return ProcessBio(bio);
            }
        }

        /// <summary>
        /// Read a file with certificates in PEM format
        /// </summary>
        /// <param name="file">The file to read</param>
        public static OpenSslList<X509Certificate> ImportPEM(FileInfo file)
        {
            using (SafeBioHandle bio = Initialize(file.OpenRead()))
            {
                return ProcessBio(bio);
            }
        }

        internal static OpenSslList<X509Certificate> ImportPEM(SafeBioHandle bio)
        {
            Native.CryptoWrapper.BIO_up_ref(bio);
            return ProcessBio(bio);
        }

        /// <summary>
        /// Read a directory with certificates in PEM format
        /// </summary>
        /// <param name="dir"></param>
        public static OpenSslList<X509Certificate> ImportPEM(DirectoryInfo dir)
        {
            return ProcessDir(dir);
        }

        private static SafeBioHandle Initialize(Stream stream)
        {
            SafeBioHandle bio = Native.CryptoWrapper.BIO_new(Native.CryptoWrapper.BIO_s_mem());

            int read = 0;
            byte[] buf = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                Span<byte> bufSpan = new Span<byte>(buf);
                while ((read = stream.Read(buf, 0, buf.Length)) > 0)
                {
                    Native.CryptoWrapper.BIO_write(bio, bufSpan.GetPinnableReference(), read);
                    Array.Clear(buf, 0, read);
                }

                return bio;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        private static OpenSslList<X509Certificate> ProcessBio(SafeBioHandle currentBio)
        {
            SafeStackHandle<SafeX509CertificateHandle> certificates = Native.StackWrapper.OPENSSL_sk_new_null<SafeX509CertificateHandle>();

            //read the (INFO) stack from the bio
            using (SafeStackHandle<SafeX509InfoHandle> currentInfoStack = Native.CryptoWrapper.PEM_X509_INFO_read_bio(currentBio, IntPtr.Zero, null, IntPtr.Zero))
            {
                //create own stack to hold certificates
                SafeX509CertificateHandle certificate;

                foreach (SafeX509InfoHandle info in currentInfoStack)
                {
                    //does not own the handle, this is just used to add to the (native) stack
                    certificate = info.X509Certificate;

                    if (certificate is null
                        || certificate.IsInvalid
                        || certificate.IsClosed)
                    {
                        continue;
                    }

                    //add a reference for the target item, so the stack "owns" it
                    certificate.AddReference();

                    //add the item to the (native) stack
                    certificates.Add(certificate);
                }
            }

            return OpenSslList<X509Certificate>.CreateFromSafeHandle(certificates);
        }

        //TODO: add exception handling
        private static OpenSslList<X509Certificate> ProcessDir(DirectoryInfo dir)
        {
            SafeStackHandle<SafeX509CertificateHandle> certificates = Native.StackWrapper.OPENSSL_sk_new_null<SafeX509CertificateHandle>();
            GetCertificates(dir, certificates);
            return OpenSslList<X509Certificate>.CreateFromSafeHandle(certificates);
        }

        private static void GetCertificates(DirectoryInfo dir, SafeStackHandle<SafeX509CertificateHandle> certificates)
        {
            foreach (FileInfo file in dir.GetFiles())
            {
                certificates.Add(ReadCertificate(file));
            }

            foreach (DirectoryInfo d in dir.GetDirectories())
            {
                GetCertificates(d, certificates);
            }
        }

        private static SafeX509CertificateHandle ReadCertificate(FileInfo file)
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
    }
}
