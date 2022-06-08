using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Keys;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Collections;

namespace OpenSSL.Core
{
    public abstract class Cipher
        : OpenSslWrapperBase,
            IStackableWrapper<SafeCipherHandle>
    {
        SafeCipherHandle ISafeHandleWrapper<SafeCipherHandle>.Handle
            => this._Handle;
        public override SafeHandle Handle
            => this._Handle;

        internal SafeCipherContextHandle CipherContextHandle { get; private set; }

        private static HashSet<string>? _SupportedCiphers;
        public static HashSet<string> SupportedCiphers
        {
            get
            {
                if (!(_SupportedCiphers is null))
                    return _SupportedCiphers;

                NameCollector collector = new NameCollector(Native.OBJ_NAME_TYPE_CIPHER_METH, true);
                return _SupportedCiphers = collector.Result;
            }
        }

        internal readonly SafeCipherHandle _Handle;

        private bool _finalized;

        protected Cipher(CipherType cipherType)
            : base()
        {
            this._Handle = CryptoWrapper.EVP_get_cipherbyname(cipherType.ShortNamePtr);
            this.CipherContextHandle = CryptoWrapper.EVP_CIPHER_CTX_new();
        }

        public int GetOutputBufferLength(Span<byte> inputBuffer)
        {
            return inputBuffer.Length + (CryptoWrapper.EVP_CIPHER_block_size(this._Handle) - 1);
        }

        protected int GetIVLength() => CryptoWrapper.EVP_CIPHER_iv_length(this._Handle);
        protected int GetKeyLength() => CryptoWrapper.EVP_CIPHER_key_length(this._Handle);

        public int GetCipherBlockSize() => CryptoWrapper.EVP_CIPHER_block_size(this._Handle);
        public int GetMaximumOutputLength(int intputLength) => this.GetCipherBlockSize() + intputLength - 1;

        //padding is enabled by default
        public void DisablePadding()
        {
            CryptoWrapper.EVP_CIPHER_CTX_set_padding(this.CipherContextHandle, 0);
        }

        protected abstract int UpdateInternal(in Span<byte> inputBuffer, ref Span<byte> outputBuffer);
        protected abstract int FinalizeInternal(ref Span<byte> outputBuffer);

        //protected static byte[] GetBufferFromKey(Key key)
        //{
        //    byte[] keyBuffer;
        //    SafeBioHandle bioHandle;
        //    using (bioHandle = Native.CryptoWrapper.BIO_new(Native.CryptoWrapper.BIO_s_mem()))
        //    {
        //        key.WriteDER(bioHandle);
        //        uint length = Native.CryptoWrapper.BIO_ctrl_pending(bioHandle);
        //        IntPtr pp = Native.CryptoWrapper.BIO_get_data(bioHandle);
        //        keyBuffer = new byte[(int)length];
        //        Marshal.Copy(pp, keyBuffer, 0, (int)length);
        //    }
        //    return keyBuffer;
        //}

        protected void BytesToKey(DigestType digestType, Span<byte> salt, Span<byte> data, int count, out byte[] key, out byte[] iv)
        {
            var keylen = this.GetKeyLength();
            if (keylen == 0)
                keylen = 8;
            key = new byte[keylen];
            Span<byte> keySpan = new Span<byte>(key);

            var ivlen = this.GetIVLength();
            if (ivlen == 0)
                ivlen = 8;
            iv = new byte[ivlen];
            Span<byte> ivSpan = new Span<byte>(iv);

            SafeMessageDigestHandle digestHandle = CryptoWrapper.EVP_get_digestbyname(digestType.ShortNamePtr);

            CryptoWrapper.EVP_BytesToKey
            (
                this._Handle,
                digestHandle,
                salt.GetPinnableReference(),
                data.GetPinnableReference(),
                data.Length,
                1,
                ref keySpan.GetPinnableReference(),
                ref ivSpan.GetPinnableReference()
            );
        }

        public int Update(in Span<byte> inputBuffer, ref Span<byte> outputBuffer)
        {
            if (this._finalized)
                throw new InvalidOperationException("Cipher has already been finalized");

            return this.UpdateInternal(in inputBuffer, ref outputBuffer);
        }

        public int Finalize(ref Span<byte> outputBuffer)
        {
            if (this._finalized)
                throw new InvalidOperationException("Cipher has already been finalized");

            int ret = this.FinalizeInternal(ref outputBuffer);
            this._finalized = true;
            return ret;
        }

        //needs to be reinitialized
        //public void Reset()
        //{
        //    CryptoWrapper.EVP_CIPHER_CTX_reset(this.CipherContextHandle);
        //}

        protected override void Dispose(bool disposing)
        {
            if (this.CipherContextHandle.IsClosed
                || this.CipherContextHandle.IsInvalid)
            {
                return;
            }

            this.CipherContextHandle.Dispose();
        }
    }
}