using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core
{
    public interface IKey
    {
        KeyType KeyType { get; }
        int Bits { get; }
        int Size { get; }
    }

    public interface IPrivateKey : IKey, IFile
    {

    }

    public interface IPublicKey : IKey
    {

    }
}
