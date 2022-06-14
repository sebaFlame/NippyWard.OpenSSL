using System;
using System.Collections.Generic;
using System.IO;

using NippyWard.OpenSSL.ASN1;

namespace NippyWard.OpenSSL
{
    public interface IFile
    {
        //T Read(string filePath, string password, FileEncoding fileEncoding = FileEncoding.PEM);
        //T Read(FileStream stream, string password, FileEncoding fileEncoding = FileEncoding.PEM);

        void Write(string filePath, string password, CipherType cipherType, FileEncoding fileEncoding = FileEncoding.PEM);
        void Write(Stream stream, string password, CipherType cipherType, FileEncoding fileEncoding = FileEncoding.PEM);
    }
}
