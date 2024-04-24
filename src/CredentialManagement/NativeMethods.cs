using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace CredentialManagement
{
    /// <summary>
    /// 
    /// </summary>
    public class NativeMethods
    {
        /// <summary>
        /// 
        /// </summary>
        public const int CREDUI_MAX_USERNAME_LENGTH = 513;
        /// <summary>
        /// 
        /// </summary>
        public const int CREDUI_MAX_PASSWORD_LENGTH = 256;
        /// <summary>
        /// 
        /// </summary>
        public const int CREDUI_MAX_MESSAGE_LENGTH = 32767;
        /// <summary>
        /// 
        /// </summary>
        public const int CREDUI_MAX_CAPTION_LENGTH = 128;
        /// <summary>
        /// 
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct CREDENTIAL
        {
            /// <summary>
            /// 
            /// </summary>
            public int Flags { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public int Type { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string TargetName;
            /// <summary>
            /// 
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Comment;
            /// <summary>
            /// 
            /// </summary>
            public long LastWritten { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public int CredentialBlobSize { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public IntPtr CredentialBlob { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public int Persist { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public int AttributeCount { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public IntPtr Attributes { get; set; }
            /// <summary>
            /// 
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string TargetAlias;
            /// <summary>
            /// 
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string UserName;
        }
        /// <summary>
        /// 
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CREDUI_INFO
        {
            /// <summary>
            /// 
            /// </summary>
            public int cbSize { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public IntPtr hwndParent { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string pszMessageText { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string pszCaptionText { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public IntPtr hbmBanner { get; set; }
        }
        /// <summary>
        /// 
        /// </summary>
        [Flags]
        internal enum WINXP_CREDUI_FLAGS
        {
            /// <summary>
            /// 
            /// </summary>
            INCORRECT_PASSWORD = 0x00001,
            /// <summary>
            /// 
            /// </summary>
            DO_NOT_PERSIST = 0x00002,
            /// <summary>
            /// 
            /// </summary>
            REQUEST_ADMINISTRATOR = 0x00004,
            /// <summary>
            /// 
            /// </summary>
            EXCLUDE_CERTIFICATES = 0x00008,
            /// <summary>
            /// 
            /// </summary>
            REQUIRE_CERTIFICATE = 0x00010,
            /// <summary>
            /// 
            /// </summary>
            SHOW_SAVE_CHECK_BOX = 0x00040,
            /// <summary>
            /// 
            /// </summary>
            ALWAYS_SHOW_UI = 0x00080,
            /// <summary>
            /// 
            /// </summary>
            REQUIRE_SMARTCARD = 0x00100,
            /// <summary>
            /// 
            /// </summary>
            PASSWORD_ONLY_OK = 0x00200,
            /// <summary>
            /// 
            /// </summary>
            VALIDATE_USERNAME = 0x00400,
            /// <summary>
            /// 
            /// </summary>
            COMPLETE_USERNAME = 0x00800,
            /// <summary>
            /// 
            /// </summary>
            PERSIST = 0x01000,
            /// <summary>
            /// 
            /// </summary>
            SERVER_CREDENTIAL = 0x04000,
            /// <summary>
            /// 
            /// </summary>
            EXPECT_CONFIRMATION = 0x20000,
            /// <summary>
            /// 
            /// </summary>
            GENERIC_CREDENTIALS = 0x40000,
            /// <summary>
            /// 
            /// </summary>
            USERNAME_TARGET_CREDENTIALS = 0x80000,
            /// <summary>
            /// 
            /// </summary>
            KEEP_USERNAME = 0x100000,
        }
        /// <summary>
        /// 
        /// </summary>
        [Flags]
        internal enum WINVISTA_CREDUI_FLAGS
        {
            /// <summary>
            /// The caller is requesting that the credential provider return the user name and password in plain text.
            /// This value cannot be combined with SECURE_PROMPT.
            /// </summary>
            CREDUIWIN_GENERIC = 0x1,
            /// <summary>
            /// The Save check box is displayed in the dialog box.
            /// </summary>
            CREDUIWIN_CHECKBOX = 0x2,
            /// <summary>
            /// Only credential providers that support the authentication package specified by the authPackage parameter should be enumerated.
            /// This value cannot be combined with CREDUIWIN_IN_CRED_ONLY.
            /// </summary>
            CREDUIWIN_AUTHPACKAGE_ONLY = 0x10,
            /// <summary>
            /// Only the credentials specified by the InAuthBuffer parameter for the authentication package specified by the authPackage parameter should be enumerated.
            /// If this flag is set, and the InAuthBuffer parameter is NULL, the function fails.
            /// This value cannot be combined with CREDUIWIN_AUTHPACKAGE_ONLY.
            /// </summary>
            CREDUIWIN_IN_CRED_ONLY = 0x20,
            /// <summary>
            /// Credential providers should enumerate only administrators. This value is intended for User Account Control (UAC) purposes only. We recommend that external callers not set this flag.
            /// </summary>
            CREDUIWIN_ENUMERATE_ADMINS = 0x100,
            /// <summary>
            /// Only the incoming credentials for the authentication package specified by the authPackage parameter should be enumerated.
            /// </summary>
            CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200,
            /// <summary>
            /// The credential dialog box should be displayed on the secure desktop. This value cannot be combined with CREDUIWIN_GENERIC.
            /// Windows Vista: This value is not supported until Windows Vista with SP1.
            /// </summary>
            CREDUIWIN_SECURE_PROMPT = 0x1000,
            /// <summary>
            /// The credential provider should align the credential BLOB pointed to by the refOutAuthBuffer parameter to a 32-bit boundary, even if the provider is running on a 64-bit system.
            /// </summary>
            CREDUIWIN_PACK_32_WOW = 0x10000000,
        }
        /// <summary>
        /// 
        /// </summary>
        internal enum CredUIReturnCodes
        {
            /// <summary>
            /// 
            /// </summary>
            NO_ERROR = 0,
            /// <summary>
            /// 
            /// </summary>
            ERROR_CANCELLED = 1223,
            /// <summary>
            /// 
            /// </summary>
            ERROR_NO_SUCH_LOGON_SESSION = 1312,
            /// <summary>
            /// 
            /// </summary>
            ERROR_NOT_FOUND = 1168,
            /// <summary>
            /// 
            /// </summary>
            ERROR_INVALID_ACCOUNT_NAME = 1315,
            /// <summary>
            /// 
            /// </summary>
            ERROR_INSUFFICIENT_BUFFER = 122,
            /// <summary>
            /// 
            /// </summary>
            ERROR_BAD_ARGUMENTS = 160,
            /// <summary>
            /// 
            /// </summary>
            ERROR_INVALID_PARAMETER = 87,
            /// <summary>
            /// 
            /// </summary>
            ERROR_INVALID_FLAGS = 1004,
        }
        /// <summary>
        /// 
        /// </summary>
        internal enum CREDErrorCodes
        {
            /// <summary>
            /// 
            /// </summary>
            NO_ERROR = 0,
            /// <summary>
            /// 
            /// </summary>
            ERROR_NOT_FOUND = 1168,
            /// <summary>
            /// 
            /// </summary>
            ERROR_NO_SUCH_LOGON_SESSION = 1312,
            /// <summary>
            /// 
            /// </summary>
            ERROR_INVALID_PARAMETER = 87,
            /// <summary>
            /// 
            /// </summary>
            ERROR_INVALID_FLAGS = 1004,
            /// <summary>
            /// 
            /// </summary>
            ERROR_BAD_USERNAME = 2202,
            /// <summary>
            /// 
            /// </summary>
            SCARD_E_NO_READERS_AVAILABLE = (int)(0x8010002E - 0x100000000),
            /// <summary>
            /// 
            /// </summary>
            SCARD_E_NO_SMARTCARD = (int)(0x8010000C - 0x100000000),
            /// <summary>
            /// 
            /// </summary>
            SCARD_W_REMOVED_CARD = (int)(0x80100069 - 0x100000000),
            /// <summary>
            /// 
            /// </summary>
            SCARD_W_WRONG_CHV = (int)(0x8010006B - 0x100000000)
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="target"></param>
        /// <param name="type"></param>
        /// <param name="reservedFlag"></param>
        /// <param name="CredentialPtr"></param>
        /// <returns></returns>
        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr CredentialPtr);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="userCredential"></param>
        /// <param name="flags"></param>
        /// <returns></returns>
        [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] UInt32 flags);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="cred"></param>
        /// <returns></returns>
        [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        internal static extern bool CredFree([In] IntPtr cred);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="target"></param>
        /// <param name="type"></param>
        /// <param name="flags"></param>
        /// <returns></returns>
        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
        internal static extern bool CredDelete(StringBuilder target, CredentialType type, int flags);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="filter"></param>
        /// <param name="flag"></param>
        /// <param name="count"></param>
        /// <param name="pCredentials"></param>
        /// <returns></returns>
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool CredEnumerateW(string filter, int flag, out uint count, out IntPtr pCredentials);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="creditUR"></param>
        /// <param name="targetName"></param>
        /// <param name="reserved1"></param>
        /// <param name="iError"></param>
        /// <param name="userName"></param>
        /// <param name="maxUserName"></param>
        /// <param name="password"></param>
        /// <param name="maxPassword"></param>
        /// <param name="pfSave"></param>
        /// <param name="flags"></param>
        /// <returns></returns>
        [DllImport("credui.dll")]
        internal static extern CredUIReturnCodes CredUIPromptForCredentials(ref CREDUI_INFO creditUR, string targetName, IntPtr reserved1, int iError, StringBuilder userName, int maxUserName, StringBuilder password, int maxPassword, [MarshalAs(UnmanagedType.Bool)] ref bool pfSave, int flags);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="notUsedHere"></param>
        /// <param name="authError"></param>
        /// <param name="authPackage"></param>
        /// <param name="InAuthBuffer"></param>
        /// <param name="InAuthBufferSize"></param>
        /// <param name="refOutAuthBuffer"></param>
        /// <param name="refOutAuthBufferSize"></param>
        /// <param name="fSave"></param>
        /// <param name="flags"></param>
        /// <returns></returns>
        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        internal static extern CredUIReturnCodes CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere, int authError, ref uint authPackage, IntPtr InAuthBuffer, uint InAuthBufferSize, out IntPtr refOutAuthBuffer, out uint refOutAuthBufferSize, ref bool fSave, int flags);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ptr"></param>
        [DllImport("ole32.dll")]
        internal static extern void CoTaskMemFree(IntPtr ptr);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="dwFlags"></param>
        /// <param name="pszUserName"></param>
        /// <param name="pszPassword"></param>
        /// <param name="pPackedCredentials"></param>
        /// <param name="pcbPackedCredentials"></param>
        /// <returns></returns>
        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean CredPackAuthenticationBuffer(int dwFlags, StringBuilder pszUserName, StringBuilder pszPassword, IntPtr pPackedCredentials, ref int pcbPackedCredentials);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="dwFlags"></param>
        /// <param name="pAuthBuffer"></param>
        /// <param name="cbAuthBuffer"></param>
        /// <param name="pszUserName"></param>
        /// <param name="pcchMaxUserName"></param>
        /// <param name="pszDomainName"></param>
        /// <param name="pcchMaxDomainame"></param>
        /// <param name="pszPassword"></param>
        /// <param name="pcchMaxPassword"></param>
        /// <returns></returns>
        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        internal static extern bool CredUnPackAuthenticationBuffer(int dwFlags, IntPtr pAuthBuffer, uint cbAuthBuffer, StringBuilder pszUserName, ref int pcchMaxUserName, StringBuilder pszDomainName, ref int pcchMaxDomainame, StringBuilder pszPassword, ref int pcchMaxPassword);
        /// <summary>
        /// 
        /// </summary>
        internal sealed class CriticalCredentialHandle : CriticalHandleZeroOrMinusOneIsInvalid
        {
            /// <summary>
            /// Set the handle.
            /// </summary>
            /// <param name="preexistingHandle"></param>
            internal CriticalCredentialHandle(IntPtr preexistingHandle)
            {
                SetHandle(preexistingHandle);
            }
            /// <summary>
            /// 
            /// </summary>
            /// <returns></returns>
            /// <exception cref="InvalidOperationException"></exception>
            internal CREDENTIAL GetCredential()
            {
                if (!IsInvalid)
                {
                    // Get the Credential from the mem location
                    return (CREDENTIAL)Marshal.PtrToStructure(handle, typeof(CREDENTIAL));
                }
                else
                {
                    throw new InvalidOperationException("Invalid CriticalHandle!");
                }
            }


            /// <summary>
            /// Perform any specific actions to release the handle in the ReleaseHandle method.
            /// Often, you need to use Pinvoke to make a call into the Win32 API to release the 
            /// handle. In this case, however, we can use the Marshal class to release the unmanaged memory.
            /// </summary>
            /// <returns></returns>
            override protected bool ReleaseHandle()
            {
                // If the handle was set, free it. Return success.
                if (!IsInvalid)
                {
                    // NOTE: We should also ZERO out the memory allocated to the handle, before free'ing it
                    // so there are no traces of the sensitive data left in memory.
                    CredFree(handle);
                    // Mark the handle as invalid for future users.
                    SetHandleAsInvalid();
                    return true;
                }
                // Return false. 
                return false;
            }
        }
    }
}
