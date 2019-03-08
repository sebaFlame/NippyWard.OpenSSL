using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles
{
    internal abstract class SafeASN1BitStringHandle : SafeAsn1StringHandle
    {
        internal SafeASN1BitStringHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeASN1BitStringHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        public Span<byte> Value
        {
            get  
            {
                int length = this.CryptoWrapper.ASN1_STRING_length(this);
                IntPtr ptr = this.CryptoWrapper.ASN1_STRING_get0_data(this);
                unsafe
                {
                    return new Span<byte>(ptr.ToPointer(), length);
                }
            }
            set
            {
                this.CryptoWrapper.ASN1_BIT_STRING_set(this, value.GetPinnableReference(), value.Length);
            }
        }

        internal override IntPtr Duplicate()
        {
            return this.CryptoWrapper.ASN1_BIT_STRING_dup(this);
        }

        /// <summary>
        /// Calls ASN1_STRING_free()
        /// </summary>
        protected override bool ReleaseHandle()
        {
            this.CryptoWrapper.ASN1_BIT_STRING_free(this.handle);
            return true;
        }
    }
}
