using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.IO.Compression;
using Microsoft.Build.Utilities;
using Microsoft.Build.Framework;
using System.ComponentModel;

namespace OpenSSL.Core.Tasks
{
    public class Unzip : Task
    {
        /// <summary>
        /// Gets or sets the name of the zip file.
        /// </summary>
        /// <value>The name of the zip file.</value>
        [Required]
        public string ZipFileName { get; set; }

        /// <summary>
        /// Gets or sets the target directory.
        /// Intermediate directories get created
        /// </summary>
        /// <value>The target directory.</value>
        [Required]
        public string TargetDirectory { get; set; }

        /// <summary>
        /// Set the file to extract to TargetDirectory
        /// </summary>
        [Required]
        public string ExtractFile { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to overwrite any existing files on extraction. Defaults to <c>true</c>.
        /// </summary>
        /// <value><c>true</c> to overwrite any existing files on extraction; otherwise, <c>false</c>.</value>
        [DefaultValue(true)]
        public bool Overwrite { get; set; }

        public override bool Execute()
        {
            string extractPath = Path.GetFullPath(this.TargetDirectory);

            if (!Directory.Exists(extractPath))
                return false;

            if (!extractPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
                extractPath = string.Concat(extractPath, Path.DirectorySeparatorChar);

            ZipArchiveEntry entry;
            string destination;
            using (ZipArchive archive = ZipFile.OpenRead(this.ZipFileName))
            {
                if((entry = archive.Entries.SingleOrDefault(x => x.Name.Equals(this.ExtractFile))) is null)
                    return false;

                destination = Path.Combine(extractPath, entry.Name);
                entry.ExtractToFile(destination);
            }

            return true;
        }
    }
}
