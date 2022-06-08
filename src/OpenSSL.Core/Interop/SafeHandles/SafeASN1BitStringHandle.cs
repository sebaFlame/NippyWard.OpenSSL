using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles
{
    internal abstract class SafeASN1BitStringHandle : SafeAsn1StringHandle
    {
        public new static SafeASN1BitStringHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeASN1BitStringHandle>(IntPtr.Zero);

        /// <summary>
        /// Calls ASN1_STRING_free()
        /// </summary>
        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static readonly OPENSSL_sk_freefunc _FreeFunc;

        static SafeASN1BitStringHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.ASN1_BIT_STRING_free);
        }

        internal SafeASN1BitStringHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeASN1BitStringHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        public Span<byte> Value
        {
            get  
            {
                int length = CryptoWrapper.ASN1_STRING_length(this);
                IntPtr ptr = CryptoWrapper.ASN1_STRING_get0_data(this);
                unsafe
                {
                    return new Span<byte>(ptr.ToPointer(), length);
                }
            }
            set
            {
                CryptoWrapper.ASN1_BIT_STRING_set(this, value.GetPinnableReference(), value.Length);
            }
        }
    }
}
