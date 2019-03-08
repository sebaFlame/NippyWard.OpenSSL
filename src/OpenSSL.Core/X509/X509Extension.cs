using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;

namespace OpenSSL.Core.X509
{
    public class X509Extension : Base
    {
        internal SafeX509ExtensionHandle ExtensionHandle;
        private X509ExtensionType extensionType;

        public string Name => this.extensionType.LongName;
        public bool Critical => this.CryptoWrapper.X509_EXTENSION_get_critical(this.ExtensionHandle) == 1;

        string data;
        public string Data => data ?? (data = this.CryptoWrapper.X509_EXTENSION_get_data(this.ExtensionHandle).Value);

        internal X509Extension(SafeX509ExtensionHandle extensionHandle)
            : base()
        {
            this.ExtensionHandle = extensionHandle;
            this.extensionType = new X509ExtensionType(this.CryptoWrapper.X509_EXTENSION_get_object(this.ExtensionHandle));
        }

        public X509Extension(string name, bool critical, string value)
            : base()
        {
            this.extensionType = name;
            this.ExtensionHandle = CreateHandle(this.extensionType, critical, value);
        }

        public X509Extension(X509ExtensionType type, bool critical, string value)
            : base()
        {
            this.extensionType = type;
            this.ExtensionHandle = CreateHandle(type, critical, value);
        }

        ~X509Extension()
        {
            this.Dispose();
        }

        //internal static SafeX509ExtensionHandle CreateHandle(X509ExtensionType type, bool critical, string value)
        //{
        //    SafeASN1OctetStringHandle stringHandle;
        //    SafeX509ExtensionHandle extensionHandle = Native.CryptoWrapper.X509_EXTENSION_new();
        //    using (stringHandle = Native.CryptoWrapper.ASN1_OCTET_STRING_new())
        //    {
        //        stringHandle.Value = value;
        //        Native.CryptoWrapper.X509_EXTENSION_create_by_NID(ref extensionHandle, type.NID, critical ? 1 : 0, stringHandle);
        //    }
        //    return extensionHandle;
        //}

        internal static SafeX509ExtensionHandle CreateHandle(X509ExtensionType type, bool critical, string value)
        {
            SafeASN1OctetStringHandle stringHandle = null;
            if (!string.IsNullOrEmpty(value))
            {
                stringHandle = Native.CryptoWrapper.ASN1_OCTET_STRING_new();
                stringHandle.Value = value;

            }
            if (!(stringHandle is null))
                return Native.CryptoWrapper.X509_EXTENSION_create_by_NID(IntPtr.Zero, type.NID, critical ? 1 : 0, stringHandle);
            else
                return Native.CryptoWrapper.X509_EXTENSION_create_by_NID(IntPtr.Zero, type.NID, critical ? 1 : 0, IntPtr.Zero);
        }

        public override void Dispose()
        {
            if (!(this.ExtensionHandle is null) || !this.ExtensionHandle.IsInvalid)
                this.ExtensionHandle.Dispose();

            if (!(this.extensionType is null))
                this.extensionType.Dispose();
        }
    }
}
