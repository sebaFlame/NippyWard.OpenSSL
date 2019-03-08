using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Keys;
using OpenSSL.Core.Interop;

namespace OpenSSL.Core.Ciphers
{
    public class CipherEncryption : Cipher
    {
        public byte[] Key { get; private set; }
        public byte[] IV { get; private set; }

        private int ivLength;

        public CipherEncryption(CipherType cipherType)
            : base(cipherType)
        {
            this.Key = new byte[this.GetKeyLength()];

            Span<byte> bufSpan = new Span<byte>(this.Key);
            this.CryptoWrapper.EVP_CIPHER_CTX_rand_key(this.CipherContextHandle, ref bufSpan.GetPinnableReference());

            if ((this.ivLength = this.GetIVLength()) > 0)
                this.IV = Interop.Random.Bytes(this.ivLength);
            else
                this.IV = Array.Empty<byte>();

            this.Initialize();
        }

        //public CipherEncryption(CipherType cipherType, Key key)
        //    : this(cipherType, GetBufferFromKey(key))
        //{ }

        public CipherEncryption(CipherType cipherType, byte[] key)
            : base(cipherType)
        {
            this.Key = key;

            if ((this.ivLength = this.GetIVLength()) > 0)
                this.IV = Interop.Random.Bytes(this.GetIVLength());
            else
                this.IV = Array.Empty<byte>();

            this.Initialize();
        }

        //public CipherEncryption(CipherType cipherType, Key key, byte[] iv)
        //    : this(cipherType, GetBufferFromKey(key), iv)
        //{ }

        public CipherEncryption(CipherType cipherType, byte[] key, byte[] iv)
            : base(cipherType)
        {
            this.Key = key;

            if ((this.ivLength = this.GetIVLength()) > 0 && !(iv is null))
                this.IV = iv;
            else
                this.IV = Array.Empty<byte>();

            this.Initialize();
        }

        public CipherEncryption(CipherType cipherType, DigestType digestType, byte[] salt, byte[] password)
            : base(cipherType)
        {
            Span<byte> saltSpan = new Span<byte>(salt);
            Span<byte> passwordSpan = new Span<byte>(password);

            this.BytesToKey(digestType, saltSpan, passwordSpan, 1, out byte[] key, out byte[] iv);

            this.Key = key;
            this.IV = iv;

            this.ivLength = this.IV.Length;

            this.Initialize();
        }

        private void Initialize()
        {
            Span<byte> key = new Span<byte>(this.Key);
            
            if (this.ivLength > 0 && !(this.IV is null))
            {
                Span<byte> iv = new Span<byte>(this.IV);
                this.CryptoWrapper.EVP_EncryptInit(this.CipherContextHandle, this.CipherHandle, key.GetPinnableReference(), iv.GetPinnableReference());
            }
            else
                this.CryptoWrapper.EVP_EncryptInit(this.CipherContextHandle, this.CipherHandle, key.GetPinnableReference(), IntPtr.Zero);
        }

        protected override int UpdateInternal(in Span<byte> inputBuffer, ref Span<byte> outputBuffer)
        {
            this.CryptoWrapper.EVP_EncryptUpdate(this.CipherContextHandle, ref outputBuffer.GetPinnableReference(), out int outl, inputBuffer.GetPinnableReference(), inputBuffer.Length);
            return outl;
        }

        protected override int FinalizeInternal(ref Span<byte> outputBuffer)
        {
            this.CryptoWrapper.EVP_EncryptFinal_ex(this.CipherContextHandle, ref outputBuffer.GetPinnableReference(), out int outl);
            return outl;
        }
    }
}
