using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace NippyWard.OpenSSL.X509
{
    /// <summary>
    /// Used for generating sequence numbers by the CertificateAuthority
    /// </summary>
    public interface ISequenceNumber
    {
        /// <summary>
        /// Returns the next available sequence number
        /// </summary>
        /// <returns></returns>
        int Next();
    }

    /// <summary>
    /// Implements the ISequenceNumber interface.
    /// The sequence number is read from a file, incremented,
    /// then written back to the file
    /// </summary>
    public class FileSerialNumber : ISequenceNumber
    {
        private readonly string path;

        /// <summary>
        /// Constructs a FileSerialNumber. The path specifies where
        /// the serial number should be read and written to.
        /// </summary>
        /// <param name="path"></param>
        public FileSerialNumber(string path)
        {
            this.path = path;
        }

        #region ISequenceNumber Members

        /// <summary>
        /// Implements the Next() method of the ISequenceNumber interface.
        /// The sequence number is read from a file, incremented,
        /// then written back to the file
        /// </summary>
        /// <returns></returns>
        public int Next()
        {
            FileInfo serialFile = new FileInfo(this.path);
            string name = serialFile.FullName.Replace('\\', '/');
            using (Mutex mutex = new Mutex(true, name))
            {
                mutex.WaitOne();
                int serial = 1;
                if (serialFile.Exists)
                {
                    using (StreamReader sr = new StreamReader(serialFile.OpenRead()))
                    {
                        string text = sr.ReadToEnd();
                        serial = Convert.ToInt32(text);
                        ++serial;
                    }
                }

                using (StreamWriter sr = new StreamWriter(serialFile.OpenWrite()))
                {
                    sr.Write(serial.ToString());
                }

                return serial;
            }
        }

        #endregion
    }

    /// <summary>
    /// Simple implementation of the ISequenceNumber interface.
    /// </summary>
    public class SimpleSerialNumber : ISequenceNumber
    {
        private int seq;

        /// <summary>
        /// Construct a SimpleSerialNumber with the initial sequence number set to 0.
        /// </summary>
        public SimpleSerialNumber()
        {
            seq = 0;
        }

        /// <summary>
        /// Construct a SimpleSerialNumber with the initial sequence number
        /// set to the value specified by the seed parameter.
        /// </summary>
        /// <param name="seed"></param>
        public SimpleSerialNumber(int seed)
        {
            seq = seed;
        }

        #region ISequenceNumber Members

        /// <summary>
        /// Returns the next available sequence number.
        /// This implementation simply increments the current
        /// sequence number and returns it.
        /// </summary>
        /// <returns></returns>
        public int Next()
        {
            return ++seq;
        }

        #endregion
    }
}
