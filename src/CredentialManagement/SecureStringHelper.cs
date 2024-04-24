using System;
using System.Runtime.InteropServices;
using System.Security;

namespace CredentialManagement
{
    /// <summary>
    /// 
    /// </summary>
    [SuppressUnmanagedCodeSecurity]
    internal static class SecureStringHelper
    {
        /// <summary>
        /// Methods
        /// </summary>
        /// <param name="plainString"></param>
        /// <returns></returns>
        internal static unsafe SecureString CreateSecureString(string plainString)
        {
            SecureString str;
            if (string.IsNullOrEmpty(plainString))
            {
                return new SecureString();
            }
            fixed (char* str2 = plainString)
            {
                char* chPtr = str2;
                str = new SecureString(chPtr, plainString.Length);
                str.MakeReadOnly();
            }
            return str;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="secureString"></param>
        /// <returns></returns>
        internal static string CreateString(SecureString secureString)
        {
            string str;
            IntPtr zero = IntPtr.Zero;
            if ((secureString == null) || (secureString.Length == 0))
            {
                return string.Empty;
            }
            try
            {
                zero = Marshal.SecureStringToBSTR(secureString);
                str = Marshal.PtrToStringBSTR(zero);
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(zero);
                }
            }
            return str;
        }
    }
}
