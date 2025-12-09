using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Text;

namespace CredentialManagement
{
    /// <summary>
    /// 
    /// </summary>
    public class Credential: IDisposable
    {
        /// <summary>
        /// 
        /// </summary>
        private static object _lockObject = new object();
        /// <summary>
        /// 
        /// </summary>
        private bool _disposed { get; set; }
        /// <summary>
        /// 
        /// </summary>
        private static SecurityPermission _unmanagedCodePermission { get; set; }
        /// <summary>
        /// 
        /// </summary>
        private CredentialType _type { get; set; }
        /// <summary>
        /// 
        /// </summary>
        private string _target { get; set; }
        /// <summary>
        /// 
        /// </summary>
        private SecureString _password { get; set; }
        /// <summary>
        /// 
        /// </summary>
        private string _username { get; set; }
        /// <summary>
        /// 
        /// </summary>
        private string _description { get; set; }
        /// <summary>
        /// 
        /// </summary>
        private DateTime _lastWriteTime { get; set; }
        /// <summary>
        /// 
        /// </summary>
        private PersistanceType _persistanceType { get; set; }
        /// <summary>
        /// 
        /// </summary>
        private bool _maxCredentialBlobSize { get; set; }
        /// <summary>
        /// 
        /// </summary>
        static Credential()
        {
            lock (_lockObject)
            {
                _unmanagedCodePermission = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public Credential()
            : this(null)
        {
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="username"></param>
        public Credential(string username)
            : this(username, null)
        {
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        public Credential(string username, string password)
            : this(username, password, null)
        {
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="target"></param>
        public Credential(string username, string password, string target)
            : this(username, password, target, CredentialType.Generic)
        {
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="target"></param>
        /// <param name="type"></param>
        public Credential(string username, string password, string target, CredentialType type)
        {
            Username = username;
            Password = password;
            Target = target;
            Type = type;
            PersistanceType = PersistanceType.Session;
            _lastWriteTime = DateTime.MinValue;
        }
        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            Dispose(true);

            // Prevent GC Collection since we have already disposed of this object
            GC.SuppressFinalize(this);
        }
        /// <summary>
        /// 
        /// </summary>
        ~Credential()
        {
            Dispose(false);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="disposing"></param>
        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    SecurePassword.Clear();
                    SecurePassword.Dispose();
                }
            }
            _disposed = true;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <exception cref="ObjectDisposedException"></exception>
        private void CheckNotDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("Credential object is already disposed.");
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public string Username {
            get
            {
                CheckNotDisposed();
                return _username;
            }
            set
            {
                CheckNotDisposed();
                _username = value;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public string Password
        {
            get
            {
                return SecureStringHelper.CreateString(SecurePassword);
            }
            set
            {
                CheckNotDisposed();
                SecurePassword = SecureStringHelper.CreateSecureString(string.IsNullOrEmpty(value) ? string.Empty : value);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public SecureString SecurePassword
        {
            get
            {
                CheckNotDisposed();
                _unmanagedCodePermission.Demand();
                return null == _password ? new SecureString() : _password.Copy();
            }
            set
            {
                CheckNotDisposed();
                if (null != _password)
                {
                    _password.Clear();
                    _password.Dispose();
                }
                _password = null == value ? new SecureString() : value.Copy();
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public string Target
        {
            get
            {
                CheckNotDisposed();
                return _target;
            }
            set
            {
                CheckNotDisposed();
                _target = value;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public string Description
        {
            get
            {
                CheckNotDisposed();
                return _description;
            }
            set
            {
                CheckNotDisposed();
                _description = value;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public DateTime LastWriteTime
        {
            get
            {
                return LastWriteTimeUtc.ToLocalTime();
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public DateTime LastWriteTimeUtc 
        { 
            get
            {
                CheckNotDisposed();
                return _lastWriteTime;
            }
            private set 
            { 
                _lastWriteTime = value; 
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public CredentialType Type
        {
            get
            {
                CheckNotDisposed();
                return _type;
            }
            set
            {
                CheckNotDisposed();
                _type = value;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        public PersistanceType PersistanceType
        {
            get
            {
                CheckNotDisposed();
                return _persistanceType;
            }
            set
            {
                CheckNotDisposed();
                _persistanceType = value;
            }
        }
        /// <summary>
        /// Maximum size in bytes of a credential that can be stored. While the API 
        /// documentation lists 512 as the max size, the current Windows SDK sets  
        /// it to 5*512 via CRED_MAX_CREDENTIAL_BLOB_SIZE in wincred.h. This has 
        /// been verified to work on Windows Server 2016 and later with Windows 10 1803 build 17134.523 and later. 
        /// <para>
        /// API Doc: https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentiala
        /// </para>
        /// </summary>
        /// <remarks>
        /// This only controls the guard in the library. The actual underlying OS
        /// controls the actual limit. Operating Systems older than Windows Server
        /// 2016 may only support 512 bytes.
        /// <para>
        /// Tokens often are 1040 bytes or more.
        /// </para>
        /// </remarks>
        public bool MaxCredentialBlobSize
        {
            get
            {
                CheckNotDisposed();
                return _maxCredentialBlobSize;
            }
            set
            {
                CheckNotDisposed();
                _maxCredentialBlobSize = value;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public bool Save()
        {
            CheckNotDisposed();
            _unmanagedCodePermission.Demand();

            // CRED_MAX_CREDENTIAL_BLOB_SIZE is 2560
            // https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentiala
            if (Password.Length > (MaxCredentialBlobSize ? 2560 : 512))
            {
                throw new ArgumentOutOfRangeException($"The password has exceeded {(MaxCredentialBlobSize ? 2560 : 512)} bytes.");
            }

            NativeMethods.CREDENTIAL credential = new NativeMethods.CREDENTIAL();

            try
            {
                credential.TargetName = Target;
                credential.UserName = Username;
                credential.CredentialBlob = Marshal.StringToCoTaskMemUni(Password);
                credential.CredentialBlobSize = Encoding.Unicode.GetBytes(Password).Length;
                credential.Comment = Description;
                credential.Type = (int)Type;
                credential.Persist = (int)PersistanceType;

                bool result = NativeMethods.CredWrite(ref credential, 0);
                if (!result)
                {
                    return false;
                }
                LastWriteTimeUtc = DateTime.UtcNow;
                return true;
            }
            finally
            {
                if (credential.CredentialBlob != default)
                    Marshal.FreeCoTaskMem(credential.CredentialBlob);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public bool Delete()
        {
            CheckNotDisposed();
            _unmanagedCodePermission.Demand();

            if (string.IsNullOrEmpty(Target))
            {
                throw new InvalidOperationException("Target must be specified to delete a credential.");
            }

            StringBuilder target = string.IsNullOrEmpty(Target) ? new StringBuilder() : new StringBuilder(Target);
            bool result = NativeMethods.CredDelete(target, Type, 0);
            return result;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public bool Load()
        {
            CheckNotDisposed();
            _unmanagedCodePermission.Demand();

            IntPtr credPointer = default;
            try
            {
                bool result = NativeMethods.CredRead(Target, Type, 0, out credPointer);
                if (!result)
                {
                    return false;
                }
                using (NativeMethods.CriticalCredentialHandle credentialHandle = new NativeMethods.CriticalCredentialHandle(credPointer))
                {
                    LoadInternal(credentialHandle.GetCredential());
                }
                return true;
            }
            finally
            {
                if (credPointer != default)
                    credPointer = IntPtr.Zero;
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public bool Exists()
        {
            CheckNotDisposed();
            _unmanagedCodePermission.Demand();

            if (string.IsNullOrEmpty(Target))
            {
                throw new InvalidOperationException("Target must be specified to check existance of a credential.");
            }

            using (Credential existing = new Credential { Target = Target, Type = Type })
            {
                return existing.Load();
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="credential"></param>
        internal void LoadInternal(NativeMethods.CREDENTIAL credential)
        {
            Username = credential.UserName;
            if (credential.CredentialBlobSize > 0)
            {
                Password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);
            }
            Target = credential.TargetName;
            Type = (CredentialType)credential.Type;
            PersistanceType = (PersistanceType)credential.Persist;
            Description = credential.Comment;
            LastWriteTimeUtc = DateTime.FromFileTimeUtc(credential.LastWritten);
        }
    }
}