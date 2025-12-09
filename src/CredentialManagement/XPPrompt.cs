using System;
using System.ComponentModel;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;

namespace CredentialManagement
{
	/// <summary>
	/// 
	/// </summary>
	public class XPPrompt : BaseCredentialsPrompt
	{
		/// <summary>
		/// 
		/// </summary>
		private string _target { get; set; }
		/// <summary>
		/// 
		/// </summary>
		private Bitmap _banner { get; set; }
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
				if (string.IsNullOrEmpty(value))
				{
					throw new ArgumentNullException("value");
				}
				_target = value;
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public Bitmap Banner
		{
			get
			{
				CheckNotDisposed();
				return _banner;
			}
			set
			{
				CheckNotDisposed();
				if (null != _banner)
				{
					_banner.Dispose();
				}
				_banner = value;
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool CompleteUsername
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.COMPLETE_USERNAME & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.COMPLETE_USERNAME);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool DoNotPersist
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.DO_NOT_PERSIST & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.DO_NOT_PERSIST);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool ExcludeCertificates
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.EXCLUDE_CERTIFICATES & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.EXCLUDE_CERTIFICATES);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool ExpectConfirmation
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.EXPECT_CONFIRMATION & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.EXPECT_CONFIRMATION);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool IncorrectPassword
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.INCORRECT_PASSWORD & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.INCORRECT_PASSWORD);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool Persist
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.PERSIST & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.PERSIST);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool RequestAdministrator
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.REQUEST_ADMINISTRATOR & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.REQUEST_ADMINISTRATOR);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool RequireCertificate
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.REQUIRE_CERTIFICATE & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.REQUIRE_CERTIFICATE);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool RequireSmartCard
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.REQUIRE_SMARTCARD & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.REQUIRE_SMARTCARD);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool UsernameReadOnly
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.KEEP_USERNAME & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.KEEP_USERNAME);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool ValidateUsername
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.VALIDATE_USERNAME & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.VALIDATE_USERNAME);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public override bool ShowSaveCheckBox
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.SHOW_SAVE_CHECK_BOX & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.SHOW_SAVE_CHECK_BOX);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public override bool GenericCredentials
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.GENERIC_CREDENTIALS & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.GENERIC_CREDENTIALS);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		public bool AlwaysShowUI
		{
			get
			{
				CheckNotDisposed();
				return 0 != ((int)NativeMethods.WINXP_CREDUI_FLAGS.ALWAYS_SHOW_UI & DialogFlags);
			}
			set
			{
				CheckNotDisposed();
				AddFlag(value, (int)NativeMethods.WINXP_CREDUI_FLAGS.ALWAYS_SHOW_UI);
			}
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="owner"></param>
		/// <returns></returns>
		protected override NativeMethods.CREDUI_INFO CreateCREDUI_INFO(IntPtr owner)
		{
			NativeMethods.CREDUI_INFO info = base.CreateCREDUI_INFO(owner);
			info.hbmBanner = null == Banner ? IntPtr.Zero : Banner.GetHbitmap();
			return info;
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="owner"></param>
		/// <returns></returns>
		/// <exception cref="InvalidOperationException"></exception>
		public override DialogResult ShowDialog(IntPtr owner)
		{
			CheckNotDisposed();

			NativeMethods.CREDUI_INFO credUI = CreateCREDUI_INFO(owner);

			StringBuilder usernameBuffer = new StringBuilder(1000);
			StringBuilder passwordBuffer = new StringBuilder(1000);

			bool persist = SaveChecked;

			if (string.IsNullOrEmpty(Target))
			{
				throw new InvalidOperationException("Target must always be specified.");
			}

			if (AlwaysShowUI && !GenericCredentials)
			{
				throw new InvalidOperationException("AlwaysShowUI must be specified with GenericCredentials property.");
			}

			NativeMethods.CredUIReturnCodes result = NativeMethods.CredUIPromptForCredentials(ref credUI, Target,
																				  IntPtr.Zero, ErrorCode, usernameBuffer,
																				  NativeMethods.CREDUI_MAX_USERNAME_LENGTH,
																				  passwordBuffer,
																				  NativeMethods.CREDUI_MAX_PASSWORD_LENGTH,
																				  ref persist, DialogFlags);
			switch (result)
			{
				case NativeMethods.CredUIReturnCodes.ERROR_CANCELLED:
					return DialogResult.Cancel;
				case NativeMethods.CredUIReturnCodes.ERROR_NO_SUCH_LOGON_SESSION:
				case NativeMethods.CredUIReturnCodes.ERROR_NOT_FOUND:
				case NativeMethods.CredUIReturnCodes.ERROR_INVALID_ACCOUNT_NAME:
				case NativeMethods.CredUIReturnCodes.ERROR_INSUFFICIENT_BUFFER:
				case NativeMethods.CredUIReturnCodes.ERROR_INVALID_PARAMETER:
				case NativeMethods.CredUIReturnCodes.ERROR_INVALID_FLAGS:
				case NativeMethods.CredUIReturnCodes.ERROR_BAD_ARGUMENTS:
					throw new InvalidOperationException("Invalid properties were specified.", new Win32Exception(Marshal.GetLastWin32Error()));
			}

			Username = usernameBuffer.ToString();
			Password = passwordBuffer.ToString();

			// After use, explicitly zero out
			if (passwordBuffer.Length > 0)
			{
				passwordBuffer.Remove(0, passwordBuffer.Length);
				passwordBuffer.Capacity = 0;
				passwordBuffer = null;
			}

			return DialogResult.OK;
		}
	}
}
