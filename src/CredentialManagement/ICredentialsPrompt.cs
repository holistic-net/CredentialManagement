using System;
using System.Security;

namespace CredentialManagement
{
    /// <summary>
    /// 
    /// </summary>
    interface ICredentialsPrompt: IDisposable
    {
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        DialogResult ShowDialog();
        /// <summary>
        /// 
        /// </summary>
        /// <param name="owner"></param>
        /// <returns></returns>
        DialogResult ShowDialog(IntPtr owner);
        /// <summary>
        /// 
        /// </summary>
        string Username { get; set; }
        /// <summary>
        /// 
        /// </summary>
        string Password { get; set; }
        /// <summary>
        /// 
        /// </summary>
        SecureString SecurePassword { get; set; }
        /// <summary>
        /// 
        /// </summary>
        string Title { get; set; }
        /// <summary>
        /// 
        /// </summary>
        string Message { get; set; }
        /// <summary>
        /// 
        /// </summary>
        bool SaveChecked { get; set; }
        /// <summary>
        /// 
        /// </summary>
        bool GenericCredentials { get; set; }
        /// <summary>
        /// 
        /// </summary>
        bool ShowSaveCheckBox { get; set; }
        /// <summary>
        /// 
        /// </summary>
        int ErrorCode { get; set; }
    }
}
