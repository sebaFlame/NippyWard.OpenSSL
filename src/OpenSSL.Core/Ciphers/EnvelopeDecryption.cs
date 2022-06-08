using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Keys;

namespace OpenSSL.Core.Ciphers
{
    public class EnvelopeDecryption : Cipher
    {
        public PrivateKey PrivateKey { get; private set; }

        public byte[] EncryptionKey { get; private set; }
        public byte[] IV { get; private set; }

        private readonly int _ivLength;

        public EnvelopeDecryption(CipherType cipherType, PrivateKey privKey, byte[] key)
            : base(cipherType)
        {
            this.PrivateKey = privKey;
            this.EncryptionKey = key;
            this.IV = Array.Empty<byte>();

            this.Initialize();
        }

        public EnvelopeDecryption(CipherType cipherType, PrivateKey privKey, byte[] key, byte[] iv)
            : base(cipherType)
        {
            this.PrivateKey = privKey;
            this.EncryptionKey = key;

            if ((this._ivLength = this.GetIVLength()) > 0 && !(iv is null))
                this.IV = iv;
            else
                this.IV = Array.Empty<byte>();

            this.Initialize();
        }

        private void Initialize()
        {
            Span<byte> keySpan = new Span<byte>(this.EncryptionKey);

            if (this._ivLength > 0 && !(this.IV is null))
            {
                Span<byte> ivSpan = new Span<byte>(this.IV);
                CryptoWrapper.EVP_OpenInit(this.CipherContextHandle, this._Handle,
                    keySpan.GetPinnableReference(),
                    keySpan.Length,
                    ivSpan.GetPinnableReference(),
                    this.PrivateKey._Handle);
            }
            else
            {
                CryptoWrapper.EVP_OpenInit(this.CipherContextHandle, this._Handle,
                    keySpan.GetPinnableReference(),
                    keySpan.Length,
                    IntPtr.Zero,
                    this.PrivateKey._Handle);
            }
        }

        protected override int UpdateInternal(in Span<byte> inputBuffer, ref Span<byte> outputBuffer)
        {
            CryptoWrapper.EVP_DecryptUpdate(this.CipherContextHandle, ref outputBuffer.GetPinnableReference(), out int outl, inputBuffer.GetPinnableReference(), inputBuffer.Length);
            return outl;
        }

        protected override int FinalizeInternal(ref Span<byte> outputBuffer)
        {
            CryptoWrapper.EVP_OpenFinal(this.CipherContextHandle, ref outputBuffer.GetPinnableReference(), out int outl);
            return outl;
        }
    }
}
