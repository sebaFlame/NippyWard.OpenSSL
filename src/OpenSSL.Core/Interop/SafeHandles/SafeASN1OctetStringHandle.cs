using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.Interop.SafeHandles
{
    internal abstract class SafeASN1OctetStringHandle : SafeAsn1StringHandle, IComparable<SafeASN1OctetStringHandle>
    {
        internal SafeASN1OctetStringHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeASN1OctetStringHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        public int Length => CryptoWrapper.ASN1_STRING_length(this);

        public string Value
        {
            //TODO: needs to print to a BIO using X509V3_EXT_print
            get => Native.PtrToStringAnsi(CryptoWrapper.ASN1_STRING_get0_data(this), this.Length, false);
            //TODO: is this correct????
            set
            {
                unsafe
                {
                    ReadOnlySpan<char> span = value.AsSpan();
                    fixed (char* c = span)
                    {
                        int length = Encoding.ASCII.GetEncoder().GetByteCount(c, span.Length, false);
                        byte* b = stackalloc byte[length];
                        Encoding.ASCII.GetEncoder().GetBytes(c, span.Length, b, length, true);
                        Span<byte> buf = new Span<byte>(b, length);
                        CryptoWrapper.ASN1_OCTET_STRING_set(this, buf.GetPinnableReference(), length);
                    }
                }
            }
        }

        public int CompareTo(SafeASN1OctetStringHandle other)
        {
            return CryptoWrapper.ASN1_OCTET_STRING_cmp(this, other);
        }

        /// <summary>
        /// Calls ASN1_STRING_free()
        /// </summary>
        protected override bool ReleaseHandle()
        {
            CryptoWrapper.ASN1_OCTET_STRING_free(this.handle);
            return true;
        }
    }
}
