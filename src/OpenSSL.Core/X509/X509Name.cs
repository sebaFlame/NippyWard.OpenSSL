using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.X509;

namespace OpenSSL.Core.X509
{
    public class X509Name : Base
    {
        internal SafeX509NameHandle NameHandle { get; private set; }

        /// <summary>
        /// Accessor to the name entry for 'CN'
        /// </summary>
        public string Common
        {
            get => this.GetTextByName("CN");
            set => this.AddEntryByName("CN", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'C'
        /// </summary>
        public string Country
        {
            get => this.GetTextByName("C");
            set => this.AddEntryByName("C", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'L'
        /// </summary>
        public string Locality
        {
            get => this.GetTextByName("L");
            set => this.AddEntryByName("L", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'ST'
        /// </summary>
        public string StateOrProvince
        {
            get => this.GetTextByName("ST");
            set => this.AddEntryByName("ST", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'O'
        /// </summary>
        public string Organization
        {
            get => this.GetTextByName("O");
            set => this.AddEntryByName("O", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'OU'
        /// </summary>
        public string OrganizationUnit
        {
            get => this.GetTextByName("OU");
            set => this.AddEntryByName("OU", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'G'
        /// </summary>
        public string Given
        {
            get => this.GetTextByName("G");
            set => this.AddEntryByName("G", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'S'
        /// </summary>
        public string Surname
        {
            get => this.GetTextByName("S");
            set => this.AddEntryByName("S", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'I'
        /// </summary>
        public string Initials
        {
            get => this.GetTextByName("I");
            set => this.AddEntryByName("I", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'UID'
        /// </summary>
        public string UniqueIdentifier
        {
            get => this.GetTextByName("UID");
            set => this.AddEntryByName("UID", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'T'
        /// </summary>
        public string Title
        {
            get => this.GetTextByName("T");
            set => this.AddEntryByName("T", value);
        }

        /// <summary>
        /// Accessor to the name entry for 'D'
        /// </summary>
        public string Description
        {
            get => this.GetTextByName("D");
            set => this.AddEntryByName("D", value);
        }

        internal X509Name(SafeX509NameHandle nameHandle)
            : base()
        {
            this.NameHandle = nameHandle;
        }

        private void AddEntryByName(string field, string value)
        {
            unsafe
            {
                fixed (char* fieldChar = field.AsSpan(), valChar = value.AsSpan())
                {
                    int byteCount = Encoding.ASCII.GetEncoder().GetByteCount(fieldChar, field.Length, false);
                    byte* fieldEncoded = stackalloc byte[byteCount];
                    Encoding.ASCII.GetEncoder().Convert(fieldChar, field.Length, fieldEncoded, byteCount, true, out int charsUsed, out int bytesUsed, out bool completed);
                    Span<byte> fieldSpan = new Span<byte>(fieldEncoded, byteCount);

                    byteCount = Encoding.ASCII.GetEncoder().GetByteCount(valChar, value.Length, false);
                    byte* valEncoded = stackalloc byte[byteCount];
                    Encoding.ASCII.GetEncoder().Convert(valChar, value.Length, valEncoded, byteCount, true, out charsUsed, out bytesUsed, out completed);
                    Span<byte> valSpan = new Span<byte>(valEncoded, byteCount);

                    this.CryptoWrapper.X509_NAME_add_entry_by_txt(this.NameHandle,
                        fieldSpan.GetPinnableReference(),
                        Native.MBSTRING_ASC,
                        valSpan.GetPinnableReference(),
                        valSpan.Length,
                        -1,
                        0);
                }
            }
        }

        private string GetTextByName(string field)
        {
            //get NID of the field
            int nid = this.CryptoWrapper.OBJ_txt2nid(field);

            //get length of the value of the field
            int length = this.CryptoWrapper.X509_NAME_get_text_by_NID(this.NameHandle, nid, IntPtr.Zero, 0);
            length++; //make room for final null

            string val = string.Empty;
            unsafe
            {
                byte* valBytes = stackalloc byte[length];
                Span<byte> valSpan = new Span<byte>(valBytes, length);
                this.CryptoWrapper.X509_NAME_get_text_by_NID(this.NameHandle, nid, ref valSpan.GetPinnableReference(), length);
                val = Encoding.ASCII.GetString(valBytes, length -1);
            }

            return val;
        }

        public override void Dispose()
        {
            if (!(this.NameHandle is null) && !this.NameHandle.IsInvalid)
                this.NameHandle.Dispose();
        }
    }
}
