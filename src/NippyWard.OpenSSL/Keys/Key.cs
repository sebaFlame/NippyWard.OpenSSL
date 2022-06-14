using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Linq;
using System.Runtime.InteropServices;
using System.Buffers;

using NippyWard.OpenSSL.ASN1;
using NippyWard.OpenSSL.Interop.SafeHandles.Crypto;
using NippyWard.OpenSSL.Interop.SafeHandles;
using NippyWard.OpenSSL.Interop;
using NippyWard.OpenSSL.Interop.SafeHandles.X509;
using NippyWard.OpenSSL.Collections;

namespace NippyWard.OpenSSL.Keys
{
    public abstract class Key
        : OpenSslWrapperBase,
            IEquatable<Key>,
            ISafeHandleWrapper<SafeKeyHandle>
    {
        SafeKeyHandle ISafeHandleWrapper<SafeKeyHandle>.Handle
            => this._Handle;
        public override SafeHandle Handle
            => this._Handle;

        public abstract KeyType KeyType { get; }

        public int Bits => CryptoWrapper.EVP_PKEY_bits(this._Handle);
        public int Size => CryptoWrapper.EVP_PKEY_size(this._Handle);

        internal readonly SafeKeyHandle _Handle;

        internal Key(SafeKeyHandle keyHandle)
            : base()
        {
            this._Handle = keyHandle;
        }

        public KeyContext CreateEncryptionContext()
        {
            SafeKeyContextHandle keyContext = CryptoWrapper.EVP_PKEY_CTX_new(this._Handle, SafeEngineHandle.Zero);
            CryptoWrapper.EVP_PKEY_encrypt_init(keyContext);
            return new KeyContext(keyContext);
        }

        public ulong EncryptedLength
        (
            in KeyContext keyContext,
            ReadOnlySpan<byte> buffer
        )
        {
            nuint encryptedLength = 0;

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
            nuint len = (uint)encrypted.Length;

            //encrypt the buffer
            CryptoWrapper.EVP_PKEY_encrypt
            (
                keyContext._keyContextHandle,
                ref MemoryMarshal.GetReference(encrypted),
                ref len,
                in MemoryMarshal.GetReference(buffer),
                (uint)buffer.Length
            );

            encryptedLength = len;
        }

        public KeyContext CreateDecryptionContext()
        {
            SafeKeyContextHandle keyContext = CryptoWrapper.EVP_PKEY_CTX_new(this._Handle, SafeEngineHandle.Zero);
            CryptoWrapper.EVP_PKEY_decrypt_init(keyContext);
            return new KeyContext(keyContext);
        }

        public ulong DecryptedLength
        (
            in KeyContext keyContext,
            ReadOnlySpan<byte> buffer
        )
        {
            nuint decryptedLength = 0;

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
            nuint len = (uint)decrypted.Length;

            //decrypt the buffer
            CryptoWrapper.EVP_PKEY_decrypt
            (
                keyContext._keyContextHandle,
                ref MemoryMarshal.GetReference(decrypted),
                ref len,
                in MemoryMarshal.GetReference(buffer),
                (uint)buffer.Length
            );

            decryptedLength = len;
        }

        public bool Equals(Key? other)
        {
            return CryptoWrapper.EVP_PKEY_cmp
            (
                this._Handle,
                other is null
                    ? SafeKeyHandle.Zero
                    : other._Handle
            ) == 1;
        }

        public override bool Equals(object? obj)
        {
            if(obj is null)
            {
                return false;
            }

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
