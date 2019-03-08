using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop.SafeHandles;

namespace OpenSSL.Core.ASN1
{
    public class X509ExtensionType : ASN1Object
    {
        public static X509ExtensionType SubjectKeyIdentifier = new X509ExtensionType("subjectKeyIdentifier");
        public static X509ExtensionType AuthorityKeyIdentifier = new X509ExtensionType("authorityKeyIdentifier");
        public static X509ExtensionType BasicConstraints = new X509ExtensionType("basicConstraints");
        public static X509ExtensionType KeyUsage = new X509ExtensionType("keyUsage");

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
