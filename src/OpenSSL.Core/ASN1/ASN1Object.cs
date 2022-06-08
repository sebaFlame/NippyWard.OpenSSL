using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Collections;

namespace OpenSSL.Core.ASN1
{
    public class ASN1Object
        : OpenSslWrapperBase,
            IStackableWrapper<SafeAsn1ObjectHandle>
    {
        SafeAsn1ObjectHandle ISafeHandleWrapper<SafeAsn1ObjectHandle>.Handle
            => this._Handle;
        public override SafeHandle Handle
            => this._Handle;

        private int _nid;
        public int NID
        {
            get
            {
                return _nid == 0  
                    ? (_nid = CryptoWrapper.OBJ_obj2nid(this._Handle))
                    : _nid;
            }
        }

        private string? _longName;
        public string LongName
        {
            get
            {
                return string.IsNullOrEmpty(_longName)
                    ? _longName = Native.PtrToStringAnsi(CryptoWrapper.OBJ_nid2ln(this.NID), false)
                    : _longName;
            }
        }

        private string? _shortName;
        public string ShortName
        {
            get
            {
                return string.IsNullOrEmpty(_shortName)
                    ? _shortName = Native.PtrToStringAnsi(CryptoWrapper.OBJ_nid2sn(this.NID), false)
                    : _shortName;
            }
        }

        internal IntPtr ShortNamePtr => this._Handle.ShortName;

        internal readonly SafeAsn1ObjectHandle _Handle;

        internal ASN1Object(SafeAsn1ObjectHandle asn1Handle)
            : base()
        {
            this._Handle = asn1Handle;
        }

        public ASN1Object(int nid)
            : this(CreateHandle(nid))
        { }

        public ASN1Object(string name)
            : this(CreateHandle(name))
        { }

        internal static SafeAsn1ObjectHandle CreateHandle(int nid)
            => Native.CryptoWrapper.OBJ_nid2obj(nid);

        internal static SafeAsn1ObjectHandle CreateHandle(string name)
        {
            ReadOnlySpan<char> nameSpan = name.AsSpan();
            unsafe
            {
                fixed (char* ch = nameSpan)
                {
                    int count = Encoding.ASCII.GetEncoder().GetByteCount(ch, nameSpan.Length, false);
                    //+ 1 to allow for null terminator
                    byte* b = stackalloc byte[count + 1];
                    Encoding.ASCII.GetEncoder().GetBytes(ch, nameSpan.Length, b, count, true);
                    Span<byte> buf = new Span<byte>(b, count + 1);
                    return Native.CryptoWrapper.OBJ_txt2obj(buf.GetPinnableReference(), 0);
                }
            }
        }

        //does not need to be disposed, free shouldn't do anything
        protected override void Dispose(bool disposing)
        {
            //NOP
        }
    }
}
