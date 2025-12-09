using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace CredentialManagement
{
	/// <summary>
	/// 
	/// </summary>
	public class CredentialSet : List<Credential>, IDisposable
	{
		/// <summary>
		/// 
		/// </summary>
		private bool _disposed { get; set; }
		/// <summary>
		/// 
		/// </summary>
		public CredentialSet()
		{
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="target"></param>
		/// <exception cref="ArgumentNullException"></exception>
		public CredentialSet(string target)
			: this()
		{
			if (string.IsNullOrEmpty(target))
			{
				throw new ArgumentNullException("target");
			}
			Target = target;
		}
		/// <summary>
		/// 
		/// </summary>
		public string Target { get; set; }
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
		~CredentialSet()
		{
			Dispose(false);
		}
		/// <summary>
		/// 
		/// </summary>
		/// <param name="disposing"></param>
		private void Dispose(bool disposing)
		{
			if (!_disposed && disposing && Count > 0)
			{
				ForEach(cred => { if (cred != null) { cred.Dispose(); } });
			}
			_disposed = true;
		}
		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		public CredentialSet Load()
		{
			LoadInternal();
			return this;
		}
		/// <summary>
		/// 
		/// </summary>
		private void LoadInternal()
		{
			uint count;

			IntPtr pCredentials = IntPtr.Zero;
			bool result = NativeMethods.CredEnumerateW(Target, 0, out count, out pCredentials);
			if (!result)
			{
				Trace.WriteLine(string.Format("Win32Exception: {0}", new Win32Exception(Marshal.GetLastWin32Error())));
				return;
			}

			// Read in all of the pointers first
			IntPtr[] ptrCredList = new IntPtr[count];
			for (int i = 0; i < count; i++)
			{
				ptrCredList[i] = Marshal.ReadIntPtr(pCredentials, IntPtr.Size * i);
			}

			// Now let's go through all of the pointers in the list
			// and create our Credential object(s)
			List<NativeMethods.CriticalCredentialHandle> credentialHandles =
				ptrCredList.Select(ptrCred => new NativeMethods.CriticalCredentialHandle(ptrCred)).ToList();

			IEnumerable<Credential> existingCredentials = credentialHandles
				.Select(handle => handle.GetCredential())
				.Select(nativeCredential =>
							{
								Credential credential = new Credential();
								credential.LoadInternal(nativeCredential);
								return credential;
							});
			AddRange(existingCredentials);

			// The individual credentials should not be free'd
			credentialHandles.ForEach(handle => handle.SetHandleAsInvalid());

			// Clean up memory to the Enumeration pointer
			NativeMethods.CredFree(pCredentials);
		}
	}
}