using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CredentialManagement
{
    /// <summary>
    /// 
    /// </summary>
    public enum String_Format
    {
        /// <summary>
        /// 
        /// </summary>
        Unicode,
        /// <summary>
        /// 
        /// </summary>
        Ansi
    }
    /// <summary>
    /// 
    /// </summary>
    internal abstract class String_Format_Provider
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <returns></returns>
        public abstract byte[] GetBytes(string Value);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <returns></returns>
        public abstract IntPtr StringToCoTaskMem(string Value);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <param name="Size"></param>
        /// <returns></returns>
        public abstract string PtrToString(IntPtr Value, int Size);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Format"></param>
        /// <returns></returns>
        public static String_Format_Provider GetProvider(String_Format Format)
        {
            String_Format_Provider ret = default;

            switch (Format)
            {
                case String_Format.Ansi:
                    ret = new Ansi_String_Format_Provider();
                    break;
                case String_Format.Unicode:
                    ret = new Unicode_String_Format_Provider();
                    break;
                default:
                    break;
            }

            return ret;
        }
    }
    /// <summary>
    /// 
    /// </summary>
    internal class Ansi_String_Format_Provider : String_Format_Provider
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <returns></returns>
        public override byte[] GetBytes(string Value)
        {
            return Encoding.ASCII.GetBytes(Value);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <returns></returns>
        public override IntPtr StringToCoTaskMem(string Value)
        {
            return Marshal.StringToCoTaskMemAnsi(Value);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <param name="Size"></param>
        /// <returns></returns>
        public override string PtrToString(IntPtr Value, int Size)
        {
            return Marshal.PtrToStringAnsi(Value, Size);
        }
    }
    /// <summary>
    /// 
    /// </summary>
    internal class Unicode_String_Format_Provider : String_Format_Provider
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <returns></returns>
        public override byte[] GetBytes(string Value)
        {
            return Encoding.Unicode.GetBytes(Value);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <returns></returns>
        public override IntPtr StringToCoTaskMem(string Value)
        {
            return Marshal.StringToCoTaskMemUni(Value);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <param name="Size"></param>
        /// <returns></returns>
        public override string PtrToString(IntPtr Value, int Size)
        {
            return Marshal.PtrToStringUni(Value, Size / 2);
        }
    }
}