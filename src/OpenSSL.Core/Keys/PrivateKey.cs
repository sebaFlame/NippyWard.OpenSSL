using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
using System.Buffers;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.X509;

namespace OpenSSL.Core.Keys
{
    public abstract class PrivateKey : Key, IPrivateKey
    {
        protected PrivateKey()
            : base() { }

        internal PrivateKey(KeyInternal handleWrapper)
            : base(handleWrapper) { }

        internal PrivateKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        { }

        internal static PrivateKey GetCorrectKey(SafeKeyHandle keyHandle)
        {
            KeyType keyType = (KeyType)Native.CryptoWrapper.EVP_PKEY_base_id(keyHandle);

            switch (keyType)
            {
                case KeyType.RSA:
                    return new RSAKey(keyHandle);
                case KeyType.DSA:
                    return new DSAKey(keyHandle);
                case KeyType.DH:
                    return new DHKey(keyHandle);
                case KeyType.EC:
                    return new ECKey(keyHandle);
            }

            throw new NotSupportedException("Unsupported key type detected");
        }

        public static PrivateKey Read(string filePath, string password, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"The file {filePath} has not been found");

            using (FileStream stream = new FileStream(filePath, FileMode.Open))
                return Read(stream, password, fileEncoding);
        }

        public static PrivateKey Read(Stream stream, string password, FileEncoding fileEncoding = FileEncoding.PEM)
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

                    return GetCorrectKey(ReadKey(bio, fileEncoding, password));
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        internal static SafeKeyHandle ReadKey(SafeBioHandle bioHandle, FileEncoding fileEncoding, string password)
        {
            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            switch (fileEncoding)
            {
                case FileEncoding.PEM:
                    return Native.CryptoWrapper.PEM_read_bio_PrivateKey(bioHandle, IntPtr.Zero, pass.Callback, IntPtr.Zero);
                case FileEncoding.DER:
                    return Native.CryptoWrapper.d2i_PrivateKey_bio(bioHandle, IntPtr.Zero);
                case FileEncoding.PKCS12:
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
                                out SafeStackHandle<SafeX509CertificateHandle> ca);

                            //dispose of unnecessary handles
                            cert.Dispose();
                            ca.Dispose();

                            return pkey;
                        }
                        finally
                        {
                            pkcs12Handle.Dispose();
                        }

                    }
                default:
                    throw new ArgumentOutOfRangeException(nameof(fileEncoding), fileEncoding, "Encoding not supported");
            }
        }

        public void Write(string filePath, string password, CipherType cipherType, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            using (FileStream stream = new FileStream(filePath, FileMode.CreateNew))
                this.Write(stream, password, cipherType, fileEncoding);
        }

        public void Write(Stream stream, string password, CipherType cipherType, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            if (this.KeyWrapper.Handle is null || this.KeyWrapper.Handle.IsInvalid)
                throw new InvalidOperationException("Key has not been genrated yet");

            if (!stream.CanWrite)
                throw new InvalidOperationException("Stream is not writable");

            byte[] buf = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                int read;
                using (SafeBioHandle bio = this.CryptoWrapper.BIO_new(this.CryptoWrapper.BIO_s_mem()))
                {
                    this.WriteKey(bio, password, cipherType, fileEncoding);
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

        internal void WriteKey(SafeBioHandle bioHandle, string password, CipherType cipherType, FileEncoding fileEncoding)
        {
            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            switch (fileEncoding)
            {
                case FileEncoding.PEM:
                    {
                        SafeCipherHandle cipherHandle;
                        using (cipherHandle = this.CryptoWrapper.EVP_get_cipherbyname(cipherType.ShortNamePtr))
                            this.CryptoWrapper.PEM_write_bio_PrivateKey(bioHandle, this.KeyWrapper.Handle, cipherHandle, IntPtr.Zero, 0, pass.Callback, IntPtr.Zero);
                        break;
                    }
                case FileEncoding.DER:
                    this.CryptoWrapper.i2d_PrivateKey_bio(bioHandle, this.KeyWrapper.Handle);
                    break;
                case FileEncoding.PKCS12:
                    {
                        //TODO: cipherType incorrect? should be a PBE?
                        SafePKCS12Handle pkcs12Handle = this.CryptoWrapper.PKCS12_create(password, "", this.KeyWrapper.Handle, null, null, cipherType.NID, 0, 2048, 1, 0);
                        this.CryptoWrapper.i2d_PKCS12_bio(bioHandle, pkcs12Handle);
                        break;
                    }
                default:
                    throw new ArgumentOutOfRangeException(nameof(fileEncoding), fileEncoding, "Encoding not supported");
            }
        }
    }
}
