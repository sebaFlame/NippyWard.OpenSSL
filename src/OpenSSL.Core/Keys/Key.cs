using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Linq;
using System.Runtime.InteropServices;
using System.Buffers;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.X509;

namespace OpenSSL.Core.Keys
{
    public abstract class Key : Base, IEquatable<Key>
    {
        private SafeKeyContextHandle keyContextEncryptHandle;
        private SafeKeyContextHandle keyContextDecryptHandle;
        private SafeKeyHandle keyHandle;

        public abstract KeyType KeyType { get; }
        internal SafeKeyHandle KeyHandle => this.keyHandle ?? throw new InvalidOperationException("Key has not been generated yet");

        public int Bits => this.CryptoWrapper.EVP_PKEY_bits(this.KeyHandle);
        public int Size => this.CryptoWrapper.EVP_PKEY_size(this.KeyHandle);

        protected Key()
            : base() { }

        internal Key(SafeKeyHandle keyHandle)
            : this()
        {
            this.keyHandle = keyHandle;
        }

        ~Key()
        {
            this.Dispose();
        }

        internal abstract SafeKeyHandle GenerateKeyInternal();

        public void GenerateKey()
        {
            if (!(this.keyHandle is null))
                throw new InvalidOperationException("Key has already been generated");

            this.keyHandle = this.GenerateKeyInternal();
        }

        private void InitializeEncryptionContext()
        {
            if (!(this.keyContextEncryptHandle is null)) return;
            this.keyContextEncryptHandle = this.CryptoWrapper.EVP_PKEY_CTX_new(this.KeyHandle, null);
            this.CryptoWrapper.EVP_PKEY_encrypt_init(this.keyContextEncryptHandle); //TODO: make it possible to customize this operation after this call
        }

        public uint EncryptedLength(Span<byte> buffer)
        {
            this.InitializeEncryptionContext();

            uint encryptedLength = 0;

            //compute output buffer size
            this.CryptoWrapper.EVP_PKEY_encrypt(this.keyContextEncryptHandle, IntPtr.Zero, ref encryptedLength, buffer.GetPinnableReference(), (uint)buffer.Length);
            return encryptedLength;
        }

        public void Encrypt(Span<byte> buffer, Span<byte> encrypted, out uint encryptedLength)
        {
            this.InitializeEncryptionContext();

            encryptedLength = (uint)encrypted.Length;
            ref byte inputRef = ref buffer.GetPinnableReference();

            //encrypt the buffer
            this.CryptoWrapper.EVP_PKEY_encrypt(this.keyContextEncryptHandle, ref encrypted.GetPinnableReference(), ref encryptedLength, inputRef, (uint)buffer.Length);
        }

        private void InitializeDecryptionContext()
        {
            if (!(this.keyContextDecryptHandle is null)) return;
            this.keyContextDecryptHandle = this.CryptoWrapper.EVP_PKEY_CTX_new(this.KeyHandle, null);
            this.CryptoWrapper.EVP_PKEY_decrypt_init(this.keyContextDecryptHandle); //TODO: make it possible to customize this operation after this call
        }

        public uint DecryptedLength(Span<byte> buffer)
        {
            this.InitializeDecryptionContext();

            uint decryptedLength = 0;

            //compute output buffer size
            this.CryptoWrapper.EVP_PKEY_decrypt(this.keyContextEncryptHandle, IntPtr.Zero, ref decryptedLength, buffer.GetPinnableReference(), (uint)buffer.Length);
            return decryptedLength;
        }

        public void Decrypt(Span<byte> buffer, Span<byte> decrypted, out uint decryptedLength)
        {
            this.InitializeDecryptionContext();

            decryptedLength = (uint)decrypted.Length;
            ref byte inputRef = ref buffer.GetPinnableReference();

            //decrypt the buffer
            this.CryptoWrapper.EVP_PKEY_decrypt(this.keyContextEncryptHandle, ref decrypted.GetPinnableReference(), ref decryptedLength, inputRef, (uint)buffer.Length);
        }

        public bool Equals(Key other)
        {
            if (other.KeyHandle is null || other.KeyHandle.IsInvalid)
                throw new InvalidOperationException("Key hasn't been generated yet");

            if (this.KeyHandle is null || this.KeyHandle.IsInvalid)
                throw new InvalidOperationException("Key hasn't been generated yet");

            return this.CryptoWrapper.EVP_PKEY_cmp(this.KeyHandle, other.KeyHandle) == 1;
        }

        public override bool Equals(object obj)
        {
            if (!(obj is Key key))
                return false;

            return this.Equals(key);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public override void Dispose()
        {
            if (!(this.keyContextEncryptHandle is null) && !this.keyContextEncryptHandle.IsInvalid)
                this.keyContextEncryptHandle.Dispose();

            if (!(this.keyContextDecryptHandle is null) && !this.keyContextDecryptHandle.IsInvalid)
                this.keyContextDecryptHandle.Dispose();

            if (!(this.keyHandle is null) && !this.keyHandle.IsInvalid)
                this.keyHandle.Dispose();
        }
    }
}
