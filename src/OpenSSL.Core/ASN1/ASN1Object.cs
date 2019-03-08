using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.ASN1
{
    public class ASN1Object : Base
    {
        private SafeAsn1ObjectHandle asn1Handle;

        private int nid;
        public int NID
        {
            get
            {
                return nid == 0  
                    ? (nid = this.CryptoWrapper.OBJ_obj2nid(this.asn1Handle))
                    : nid;
            }
        }

        private string longName;
        public string LongName
        {
            get
            {
                return string.IsNullOrEmpty(longName)
                    ? longName = Native.PtrToStringAnsi(this.CryptoWrapper.OBJ_nid2ln(this.NID), false)
                    : longName;
            }
        }

        public string shortName;
        public string ShortName
        {
            get
            {
                return string.IsNullOrEmpty(shortName)
                    ? shortName = Native.PtrToStringAnsi(this.CryptoWrapper.OBJ_nid2sn(this.NID), false)
                    : shortName;
            }
        }

        internal IntPtr ShortNamePtr => this.asn1Handle.ShortName;

        private ASN1Object()
            : base()
        { }

        internal ASN1Object(SafeAsn1ObjectHandle asn1Handle)
            : this()
        {
            this.asn1Handle = asn1Handle;
        }

        public ASN1Object(int nid)
            : this(CreateHandle(nid))
        { }

        public ASN1Object(string name)
            : this(CreateHandle(name))
        { }

        ~ASN1Object()
        {
            this.Dispose();
        }

        internal static SafeAsn1ObjectHandle CreateHandle(int nid)
        {
            try
            {
                return Native.CryptoWrapper.OBJ_nid2obj(nid);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        internal static SafeAsn1ObjectHandle CreateHandle(string name)
        {
            try
            {
                ReadOnlySpan<char> nameSpan = name.AsSpan();
                unsafe
                {
                    fixed (char* ch = nameSpan)
                    {
                        int count = Encoding.ASCII.GetEncoder().GetByteCount(ch, nameSpan.Length, false);
                        byte* b = stackalloc byte[count];
                        Encoding.ASCII.GetEncoder().GetBytes(ch, nameSpan.Length, b, count, true);
                        Span<byte> buf = new Span<byte>(b, count);
                        return Native.CryptoWrapper.OBJ_txt2obj(buf.GetPinnableReference(), 0);
                    }
                }
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public override void Dispose()
        {
            //does not need to be disposed, free shouldn't do anything
            if (!(this.asn1Handle is null) && !this.asn1Handle.IsInvalid)
                this.asn1Handle.Dispose();
        }
    }
}
