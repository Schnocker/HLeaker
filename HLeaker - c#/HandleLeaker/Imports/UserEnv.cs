using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace HandleLeaker
{
    class UserEnv
    {
        #region Functions
        [DllImport("userenv.dll")]
        public static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
        [DllImport("userenv.dll")]
        public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
        #endregion
    }
}
