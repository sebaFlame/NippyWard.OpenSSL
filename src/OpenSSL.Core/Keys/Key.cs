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
    [Wrapper(typeof(KeyInternal))]
    public abstract class Key : OpenSslWrapperBase, IEquatable<Key>
    {
        internal class KeyInternal : SafeHandleWrapper<SafeKeyHandle>
        {
            internal KeyInternal(SafeKeyHandle safeHandle)
                : base(safeHandle) { }
        }

        internal KeyInternal KeyWrapper { get; private set; }
        internal override ISafeHandleWrapper HandleWrapper => this.KeyWrapper;

        private SafeKeyContextHandle keyContextEncryptHandle;
        private SafeKeyContextHandle keyContextDecryptHandle;

        public abstract KeyType KeyType { get; }

        public int Bits => this.CryptoWrapper.EVP_PKEY_bits(this.KeyWrapper.Handle);
        public int Size => this.CryptoWrapper.EVP_PKEY_size(this.KeyWrapper.Handle);

        protected Key()
            : base() { }

        internal Key(KeyInternal handleWarpper)
            : this()
        {
            this.KeyWrapper = handleWarpper;
        }

        internal Key(SafeKeyHandle keyHandle)
            : this()
        {
            this.KeyWrapper = new KeyInternal(keyHandle);
        }

        ~Key()
        {
            this.Dispose();
        }

        internal abstract KeyInternal GenerateKeyInternal();

        public void GenerateKey()
        {
            if (!(this.KeyWrapper is null))
                throw new InvalidOperationException("Key has already been generated");

            this.KeyWrapper = this.GenerateKeyInternal();
        }

        private void InitializeEncryptionContext()
        {
            if (!(this.keyContextEncryptHandle is null)) return;
            this.keyContextEncryptHandle = this.CryptoWrapper.EVP_PKEY_CTX_new(this.KeyWrapper.Handle, null);
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
            this.keyContextDecryptHandle = this.CryptoWrapper.EVP_PKEY_CTX_new(this.KeyWrapper.Handle, null);
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
            if (other.KeyWrapper.Handle is null || other.KeyWrapper.Handle.IsInvalid)
                throw new InvalidOperationException("Key hasn't been generated yet");

            if (this.KeyWrapper.Handle is null || this.KeyWrapper.Handle.IsInvalid)
                throw new InvalidOperationException("Key hasn't been generated yet");

            return this.CryptoWrapper.EVP_PKEY_cmp(this.KeyWrapper.Handle, other.KeyWrapper.Handle) == 1;
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

        protected override void Dispose(bool disposing)
        {
            if (!(this.keyContextEncryptHandle is null) && !this.keyContextEncryptHandle.IsInvalid)
                this.keyContextEncryptHandle.Dispose();

            if (!(this.keyContextDecryptHandle is null) && !this.keyContextDecryptHandle.IsInvalid)
                this.keyContextDecryptHandle.Dispose();
        }
    }
}
