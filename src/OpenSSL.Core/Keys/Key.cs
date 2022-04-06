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

        public abstract KeyType KeyType { get; }

        public int Bits => CryptoWrapper.EVP_PKEY_bits(this.KeyWrapper.Handle);
        public int Size => CryptoWrapper.EVP_PKEY_size(this.KeyWrapper.Handle);

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

        internal abstract KeyInternal GenerateKeyInternal();

        public void GenerateKey()
        {
            if (!(this.KeyWrapper is null))
                throw new InvalidOperationException("Key has already been generated");

            this.KeyWrapper = this.GenerateKeyInternal();
        }

        public KeyContext CreateEncryptionContext()
        {
            SafeKeyContextHandle keyContext = CryptoWrapper.EVP_PKEY_CTX_new(this.KeyWrapper.Handle, SafeEngineHandle.Zero);
            CryptoWrapper.EVP_PKEY_encrypt_init(keyContext);
            return new KeyContext(keyContext);
        }

        public ulong EncryptedLength
        (
            in KeyContext keyContext,
            ReadOnlySpan<byte> buffer
        )
        {
            ulong encryptedLength = 0;

            //compute output buffer size
            CryptoWrapper.EVP_PKEY_encrypt
            (
                keyContext._keyContextHandle,
                IntPtr.Zero,
                ref encryptedLength,
                in MemoryMarshal.GetReference(buffer),
                (uint)buffer.Length
            );
            return encryptedLength;
        }

        public void Encrypt
        (
            in KeyContext keyContext,
            ReadOnlySpan<byte> buffer,
            Span<byte> encrypted,
            out ulong encryptedLength
        )
        {
            encryptedLength = (ulong)encrypted.Length;

            //encrypt the buffer
            CryptoWrapper.EVP_PKEY_encrypt
            (
                keyContext._keyContextHandle,
                ref MemoryMarshal.GetReference(encrypted),
                ref encryptedLength,
                in MemoryMarshal.GetReference(buffer),
                (uint)buffer.Length
            );
        }

        public KeyContext CreateDecryptionContext()
        {
            SafeKeyContextHandle keyContext = CryptoWrapper.EVP_PKEY_CTX_new(this.KeyWrapper.Handle, SafeEngineHandle.Zero);
            CryptoWrapper.EVP_PKEY_decrypt_init(keyContext);
            return new KeyContext(keyContext);
        }

        public ulong DecryptedLength
        (
            in KeyContext keyContext,
            ReadOnlySpan<byte> buffer
        )
        {
            ulong decryptedLength = 0;

            //compute output buffer size
            CryptoWrapper.EVP_PKEY_decrypt
            (
                keyContext._keyContextHandle,
                IntPtr.Zero,
                ref decryptedLength,
                in MemoryMarshal.GetReference(buffer),
                (uint)buffer.Length
            );
            return decryptedLength;
        }

        public void Decrypt
        (
            in KeyContext keyContext,
            ReadOnlySpan<byte> buffer,
            Span<byte> decrypted,
            out ulong decryptedLength
         )
        {
            decryptedLength = (uint)decrypted.Length;

            //decrypt the buffer
            CryptoWrapper.EVP_PKEY_decrypt
            (
                keyContext._keyContextHandle,
                ref MemoryMarshal.GetReference(decrypted),
                ref decryptedLength,
                in MemoryMarshal.GetReference(buffer),
                (uint)buffer.Length
            );
        }

        public bool Equals(Key other)
        {
            if (other.KeyWrapper.Handle is null || other.KeyWrapper.Handle.IsInvalid)
                throw new InvalidOperationException("Key hasn't been generated yet");

            if (this.KeyWrapper.Handle is null || this.KeyWrapper.Handle.IsInvalid)
                throw new InvalidOperationException("Key hasn't been generated yet");

            return CryptoWrapper.EVP_PKEY_cmp(this.KeyWrapper.Handle, other.KeyWrapper.Handle) == 1;
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
            //NOP
        }
    }
}
