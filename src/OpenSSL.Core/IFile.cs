using System;
using System.Collections.Generic;
using System.IO;

using OpenSSL.Core.ASN1;

namespace OpenSSL.Core
{
    public interface IFile
    {
        //T Read(string filePath, string password, FileEncoding fileEncoding = FileEncoding.PEM);
        //T Read(FileStream stream, string password, FileEncoding fileEncoding = FileEncoding.PEM);

        void Write(string filePath, string password, CipherType cipherType, FileEncoding fileEncoding = FileEncoding.PEM);
        void Write(Stream stream, string password, CipherType cipherType, FileEncoding fileEncoding = FileEncoding.PEM);
    }
}
