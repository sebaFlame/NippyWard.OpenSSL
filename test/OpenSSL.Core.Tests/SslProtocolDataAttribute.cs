using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

using OpenSSL.Core.SSL;

using Xunit.Sdk;

namespace OpenSSL.Core.Tests
{
    internal class SslProtocolDataAttribute : DataAttribute
    {
        private SslProtocol sslProtocol;

        public SslProtocolDataAttribute(SslProtocol sslProtocol)
        {
            this.sslProtocol = sslProtocol;

            if (sslProtocol == SslProtocol.Tls13 && Interop.Version.Library < Interop.Version.MinimumOpenSslTLS13Version)
                base.Skip = "Currently used OpenSSL library doesn't support TLS 1.3, atleast version 1.1.1 is needed.";
        }

        public override string Skip
        {
            get => base.Skip;
            set => throw new InvalidOperationException("Not allowed to set skip message");
        }

        public override IEnumerable<object[]> GetData(MethodInfo testMethod)
        {
            if (testMethod is null)
                throw new ArgumentNullException(nameof(testMethod));

            return new List<object[]>
            {
                new object[] { this.sslProtocol }
            };
        }
    }
}
