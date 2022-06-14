using System;
using System.Net;
using Microsoft.Build.Utilities;
using Microsoft.Build.Framework;

namespace NippyWard.OpenSSL.Tasks
{
    public class WebDownload : Task
    {
        #region Properties
        private string _fileName;

        /// <summary>
        /// Gets or sets the name of the local file that is to receive the data.
        /// </summary>
        /// <value>The name of the file.</value>
        [Required]
        public string FileName
        {
            get { return _fileName; }
            set { _fileName = value; }
        }

        private string _fileUri;
        private bool useDefaultCredentials;
        private string username;
        private string password;
        private string domain;

        /// <summary>
        /// Gets or sets the URI from which to download data.
        /// </summary>
        /// <value>The file URI.</value>
        [Required]
        public string FileUri
        {
            get { return _fileUri; }
            set { _fileUri = value; }
        }

        /// <summary>
        /// When true, the current user's credentials are used to authenticate against the remote web server
        /// </summary>
        /// <remarks>
        /// This value is ignored if the <see cref="Username"/> property is set to a non-empty value.</remarks>
        public bool UseDefaultCredentials
        {
            get { return useDefaultCredentials; }
            set { useDefaultCredentials = value; }
        }

        /// <summary>
        /// The username used to authenticate against the remote web server
        /// </summary>
        public string Username
        {
            get { return username; }
            set { username = value; }
        }

        /// <summary>
        /// The password used to authenticate against the remote web server. A value for <see cref="Username"/> must also be provided.
        /// </summary>
        public string Password
        {
            get { return password; }
            set { password = value; }
        }

        /// <summary>
        /// The domain of the user being used to authenticate against the remote web server. A value for <see cref="Username"/> must also be provided.
        /// </summary>
        public string Domain
        {
            get { return domain; }
            set { domain = value; }
        }

        #endregion

        /// <summary>
        /// When overridden in a derived class, executes the task.
        /// </summary>
        /// <returns>
        /// true if the task successfully executed; otherwise, false.
        /// </returns>
        public override bool Execute()
        {
            Log.LogMessage("Downloading File \"{0}\" from \"{1}\".", _fileName, _fileUri);

            try
            {
                using (WebClient client = new WebClient())
                {
                    client.Credentials = GetConfiguredCredentials();
                    client.DownloadFile(_fileUri, _fileName);
                }
            }
            catch (Exception ex)
            {
                Log.LogErrorFromException(ex);
                return false;
            }

            Log.LogMessage("Successfully Downloaded File \"{0}\" from \"{1}\"", _fileName, _fileUri);
            return true;
        }

        /// <summary>
        /// Determines which credentials to pass with the web request
        /// </summary>
        /// <returns></returns>
        public ICredentials GetConfiguredCredentials()
        {
            if (!String.IsNullOrEmpty(username))
            {
                return new NetworkCredential(username, password, domain);
            }
            if (useDefaultCredentials)
            {
                return CredentialCache.DefaultCredentials;
            }
            return null;
        }
    }
}
