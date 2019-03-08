using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.ASN1
{
    public class CipherType : ASN1Object
    {
        public static CipherType NONE = new CipherType(0);
        public static CipherType DES_ECB = new CipherType("des-ecb");
        public static CipherType DES_EDE = new CipherType("des-ede");
        public static CipherType DES_EDE3 = new CipherType("des-ede3");
        public static CipherType DES_CFB = new CipherType("des-cfb");
        public static CipherType DES_CFB1 = new CipherType("des-cfb1");
        public static CipherType DES_CFB8 = new CipherType("des-cfb8");
        public static CipherType DES_EDE_CFB = new CipherType("des-ede-cfb");
        public static CipherType DES_EDE3_CFB = new CipherType("des-ede3-cfb");
        public static CipherType DES_EDE3_CFB1 = new CipherType("des-ede3-cfb1");
        public static CipherType DES_EDE3_CFB8 = new CipherType("des-ede3-cfb8");
        public static CipherType DES_OFB = new CipherType("des-ofb");
        public static CipherType DES_EDE_OFB = new CipherType("des-ede-ofb");
        public static CipherType DES_EDE3_OFB = new CipherType("des-ede3-ofb");
        public static CipherType DES_CBC = new CipherType("des-cbc");
        public static CipherType DES_EDE_CBC = new CipherType("des-ede-cbc");
        public static CipherType DES_EDE3_CBC = new CipherType("des-ede3-cbc");
        public static CipherType DESX_CBC = new CipherType("desx-cbc");
        public static CipherType RC4 = new CipherType("rc4");
        public static CipherType RC4_40 = new CipherType("rc4-40");
        public static CipherType Idea_ECB = new CipherType("idea-ecb");
        public static CipherType Idea_CFB = new CipherType("idea-cfb");
        public static CipherType Idea_OFB = new CipherType("idea-ofb");
        public static CipherType Idea_CBC = new CipherType("idea-cbc");
        public static CipherType RC2_ECB = new CipherType("rc2-ecb");
        public static CipherType RC2_CBC = new CipherType("rc2-cbc");
        public static CipherType RC2_40_CBC = new CipherType("rc2-40-cbc");
        public static CipherType RC2_64_CBC = new CipherType("rc2-64-cbc");
        public static CipherType RC2_CFB = new CipherType("rc2-cfb");
        public static CipherType RC2_OFB = new CipherType("rc2-ofb");
        public static CipherType Blowfish_ECB = new CipherType("bf-ecb");
        public static CipherType Blowfish_CBC = new CipherType("bf-cbc");
        public static CipherType Blowfish_CFB = new CipherType("bf-cfb");
        public static CipherType Blowfish_OFB = new CipherType("bf-ofb");
        public static CipherType Cast5_ECB = new CipherType("cast5-ecb");
        public static CipherType Cast5_CBC = new CipherType("cast5-cbc");
        public static CipherType Cast5_OFB = new CipherType("cast5-ofb");
        public static CipherType AES_128_ECB = new CipherType("aes-128-ecb");
        public static CipherType AES_128_CBC = new CipherType("aes-128-cbc");
        public static CipherType AES_128_CFB1 = new CipherType("aes-128-cfb1");
        public static CipherType AES_128_CFB8 = new CipherType("aes-128-cfb8");
        public static CipherType AES_128_CFB128 = new CipherType("aes-128-cfb");
        public static CipherType AES_128_OFB = new CipherType("aes-128-ofb");
        public static CipherType AES_192_ECB = new CipherType("aes-192-ecb");
        public static CipherType AES_192_CBC = new CipherType("aes-192-cbc");
        public static CipherType AES_192_CFB1 = new CipherType("aes-192-cfb1");
        public static CipherType AES_192_CFB8 = new CipherType("aes-192-cfb8");
        public static CipherType AES_192_CFB128 = new CipherType("aes-192-cfb");
        public static CipherType AES_192_OFB = new CipherType("aes-192-ofb");
        public static CipherType AES_256_ECB = new CipherType("aes-256-ecb");
        public static CipherType AES_256_CBC = new CipherType("aes-256-cbc");
        public static CipherType AES_256_CFB1 = new CipherType("aes-256-cfb1");
        public static CipherType AES_256_CFB8 = new CipherType("aes-256-cfb8");
        public static CipherType AES_256_CFB128 = new CipherType("aes-256-cfb");
        public static CipherType AES_256_OFB = new CipherType("aes-256-ofb");

        public CipherType(int nid)
            : base(nid) { }

        public CipherType(string name)
            : base(name) { }

        public static implicit operator CipherType(string name)
        {
            return new CipherType(name);
        }

        public static implicit operator CipherType(int nid)
        {
            return new CipherType(nid);
        }
    }
}
