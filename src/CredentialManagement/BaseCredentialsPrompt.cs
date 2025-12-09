using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;

namespace CredentialManagement
{
	/// <summary>
	/// 
	/// </summary>
	public abstract class BaseCredentialsPrompt : ICredentialsPrompt
	{
		#region Fields
		/// <summary>
		/// 
		/// </summary>
		private bool _disposed { get; set; }
		/// <summary>
		/// 
		/// </summary>
		private static readonly object _lockObject = new object();
		/// <summary>
		/// 
		/// </summary>
		private string _username { get; set; }
		/// <summary>
		/// 
		/// </summary>
		private SecureString _password { get; set; }
		/// <summary>
		/// 
		/// </summary>
		private bool _saveChecked { get; set; }
		/// <summary>
		/// 
		/// </summary>
		private string _message { get; set; }
		/// <summary>
		/// 
		/// </summary>
		private string _title { get; set; }
		/// <summary>
		/// 
		/// </summary>
		private int _errorCode { get; set; }
		/// <summary>
		/// 
		/// </summary>
		private int _dialogFlags { get; set; }


		#endregion

		#region Constructor(s)



		#endregion

		#region Protected Methods
		/// <summary>
		/// 
		/// </summary>
		/// <param name="add"></param>
		/// <param name="flag"></param>
		protected void AddFlag(bool add, int flag)
		{
			if (add)
			{
				_dialogFlags |= flag;
			}
			else
			{
				_dialogFlags &= ~flag;
			}
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="owner"></param>
		/// <returns></returns>
		protected virtual NativeMethods.CREDUI_INFO CreateCREDUI_INFO(IntPtr owner)
		{
			NativeMethods.CREDUI_INFO credUI = new NativeMethods.CREDUI_INFO();
			credUI.cbSize = Marshal.SizeOf(credUI);
			credUI.hwndParent = owner;
			credUI.pszCaptionText = Title;
			credUI.pszMessageText = Message;
			return credUI;
		}

		#endregion

		#region Private Methods
		/// <summary>
		/// 
		/// </summary>
		/// <exception cref="ObjectDisposedException"></exception>
		protected void CheckNotDisposed()
		{
			if (_disposed)
			{
				throw new ObjectDisposedException("CredentialsPrompt object is already disposed.");
			}
		}

		#endregion

		#region Dispose Members
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
		~BaseCredentialsPrompt()
		{
			Dispose(false);
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="disposing"></param>
		protected virtual void Dispose(bool disposing)
		{
			if (_disposed)
			{
				return;
			}

			if (disposing)
			{
				// dispose managed resources
				if (_password != null)
				{
					try
					{
						_password.Clear();
						_password.Dispose();
					}
					finally
					{
						_password = null;
					}
				}

				// null other managed references to help GC
				_username = null;
				_message = null;
				_title = null;
			}

			// free unmanaged resources here (if any)

			_disposed = true;
		}

		#endregion

		#region Properties
		/// <summary>
		/// 
		/// </summary>
		public bool SaveChecked
		{
			get
			{
				CheckNotDisposed();
				return _saveChecked;
			}
			set
			{
				CheckNotDisposed();
				_saveChecked = value;
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public string Message
		{
			get
			{
				CheckNotDisposed();
				return _message;
			}
			set
			{
				CheckNotDisposed();
				if (string.IsNullOrEmpty(value))
				{
					throw new ArgumentNullException("value");
				}
				if (value.Length > NativeMethods.CREDUI_MAX_MESSAGE_LENGTH)
				{
					throw new ArgumentOutOfRangeException("value");
				}
				_message = value;
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public string Title
		{
			get
			{
				CheckNotDisposed();
				return _title;
			}
			set
			{
				CheckNotDisposed();
				if (string.IsNullOrEmpty(value))
				{
					throw new ArgumentNullException("value");
				}
				if (value.Length > NativeMethods.CREDUI_MAX_CAPTION_LENGTH)
				{
					throw new ArgumentOutOfRangeException("value");
				}
				_title = value;
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public string Username
		{
			get
			{
				CheckNotDisposed();
				return _username ?? string.Empty;
			}
			set
			{
				CheckNotDisposed();
				if (null == value)
				{
					throw new ArgumentNullException("value");
				}
				if (value.Length > NativeMethods.CREDUI_MAX_USERNAME_LENGTH)
				{
					throw new ArgumentOutOfRangeException("value");
				}
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
				if (null == value)
				{
					throw new ArgumentNullException("value");
				}
				if (value.Length > NativeMethods.CREDUI_MAX_PASSWORD_LENGTH)
				{
					throw new ArgumentOutOfRangeException("value");
				}
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
		public int ErrorCode
		{
			get
			{
				CheckNotDisposed();
				return _errorCode;
			}
			set
			{
				CheckNotDisposed();
				_errorCode = value;
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public abstract bool ShowSaveCheckBox { get; set; }
		/// <summary>
		/// 
		/// </summary>
		public abstract bool GenericCredentials { get; set; }
		/// <summary>
		/// 
		/// </summary>
		protected int DialogFlags
		{
			get { return _dialogFlags; }
		}

		#endregion

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		public virtual DialogResult ShowDialog()
		{
			return ShowDialog(IntPtr.Zero);
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="owner"></param>
		/// <returns></returns>
		public abstract DialogResult ShowDialog(IntPtr owner);
	}
}
