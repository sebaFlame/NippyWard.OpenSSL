using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.ASN1
{
    public class DigestType : ASN1Object
    {
        public static DigestType NONE = new DigestType(0);
        public static DigestType MD4 = new DigestType("md4");
        public static DigestType MD5 = new DigestType("md5");
        public static DigestType SHA = new DigestType("sha");
        public static DigestType SHA1 = new DigestType("sha1");
        public static DigestType SHA224 = new DigestType("sha224");
        public static DigestType SHA256 = new DigestType("sha256");
        public static DigestType SHA384 = new DigestType("sha384");
        public static DigestType SHA512 = new DigestType("sha512");
        public static DigestType RipeMD160 = new DigestType("ripemd160");

        public DigestType(int nid)
            : base(nid) { }

        public DigestType(string name)
            : base(name) { }

        public static implicit operator DigestType(string name)
        {
            return new DigestType(name);
        }

        public static implicit operator DigestType(int nid)
        {
            return new DigestType(nid);
        }
    }
}
