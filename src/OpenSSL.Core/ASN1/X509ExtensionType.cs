using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.ASN1
{
    public class X509ExtensionType : ASN1Object
    {
        public static X509ExtensionType BasicConstraints = new X509ExtensionType(87); //X509v3 Basic Constraints
        public static X509ExtensionType SubjectKeyIdentifier = new X509ExtensionType(82); //X509v3 Subject Key Identifier
        public static X509ExtensionType AuthorityKeyIdentifier = new X509ExtensionType(90); //X509v3 Authority Key Identifier
        public static X509ExtensionType KeyUsage = new X509ExtensionType(83); //X509v3 Key Usage
        public static X509ExtensionType ExtendedKeyUsage = new X509ExtensionType(126); //X509v3 Extended Key Usage
        public static X509ExtensionType OCSP = new X509ExtensionType("OCSP");
        public static X509ExtensionType CAIssuers = new X509ExtensionType("caIssuers");

        internal X509ExtensionType(SafeAsn1ObjectHandle asn1Handle)
            : base(asn1Handle) { }

        public X509ExtensionType(int nid)
            : base(nid) { }

        public X509ExtensionType(string name)
            : base(name) { }

        public static implicit operator X509ExtensionType(string name)
        {
            return new X509ExtensionType(name);
        }

        public static implicit operator X509ExtensionType(int nid)
        {
            return new X509ExtensionType(nid);
        }
    }
}
