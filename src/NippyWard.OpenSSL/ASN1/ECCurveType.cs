using System;
using System.Collections.Generic;
using System.Text;

namespace NippyWard.OpenSSL.ASN1
{
    public class ECCurveType : ASN1Object
    {
        public static ECCurveType prime_field = new ECCurveType(406);
        public static ECCurveType prime192v1 = new ECCurveType(409);
        public static ECCurveType prime192v2 = new ECCurveType(410);
        public static ECCurveType prime192v3 = new ECCurveType(411);
        public static ECCurveType prime239v1 = new ECCurveType(412);
        public static ECCurveType prime239v2 = new ECCurveType(413);
        public static ECCurveType prime239v3 = new ECCurveType(414);
        public static ECCurveType prime256v1 = new ECCurveType(415);
        public static ECCurveType c2tnb191v1 = new ECCurveType(688);
        public static ECCurveType c2tnb239v1 = new ECCurveType(694);
        public static ECCurveType secp224r1 = new ECCurveType(713);
        public static ECCurveType secp384r1 = new ECCurveType(715);
        public static ECCurveType secp521r1 = new ECCurveType(716);
        public static ECCurveType sect163k1 = new ECCurveType(721);
        public static ECCurveType sect163r2 = new ECCurveType(723);
        public static ECCurveType sect233k1 = new ECCurveType(726);
        public static ECCurveType sect233r1 = new ECCurveType(727);
        public static ECCurveType sect283k1 = new ECCurveType(729);
        public static ECCurveType sect283r1 = new ECCurveType(730);
        public static ECCurveType sect409k1 = new ECCurveType(731);
        public static ECCurveType sect409r1 = new ECCurveType(732);
        public static ECCurveType sect571k1 = new ECCurveType(733);
        public static ECCurveType sect571r1 = new ECCurveType(734);
        public static ECCurveType ipsec4 = new ECCurveType(750);

        public ECCurveType(int nid)
            : base(nid) { }

        public ECCurveType(string name)
            : base(name) { }

        public static implicit operator ECCurveType(string name)
        {
            return new ECCurveType(name);
        }

        public static implicit operator ECCurveType(int nid)
        {
            return new ECCurveType(nid);
        }
    }
}
