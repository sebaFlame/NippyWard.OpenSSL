using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.ASN1
{
    [Wrapper(typeof(ASN1ObjectInternal))]
    public class ASN1Object : OpenSslWrapperBase
    {
        internal class ASN1ObjectInternal : SafeHandleWrapper<SafeAsn1ObjectHandle>
        {
            internal ASN1ObjectInternal(SafeAsn1ObjectHandle safeHandle)
                : base(safeHandle) { }
        }

        internal ASN1ObjectInternal ASN1ObjectWrapper { get; private set; }
        internal override ISafeHandleWrapper HandleWrapper => this.ASN1ObjectWrapper;

        private int nid;
        public int NID
        {
            get
            {
                return nid == 0  
                    ? (nid = this.CryptoWrapper.OBJ_obj2nid(this.ASN1ObjectWrapper.Handle))
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

        internal IntPtr ShortNamePtr => this.ASN1ObjectWrapper.Handle.ShortName;

        private ASN1Object()
            : base()
        { }

        internal ASN1Object(ASN1ObjectInternal handleWarpper)
            : this()
        {
            this.ASN1ObjectWrapper = handleWarpper;
        }

        internal ASN1Object(SafeAsn1ObjectHandle asn1Handle)
            : this()
        {
            this.ASN1ObjectWrapper = new ASN1ObjectInternal(asn1Handle);
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

        //does not need to be disposed, free shouldn't do anything
        protected override void Dispose(bool disposing)
        {
            //NOP
        }
    }
}
