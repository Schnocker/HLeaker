using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HandleLeaker
{
    class Options
    {
        public static string TargetProcess = "Unturned";
        public static string YourProcess = "HandleLeaker.exe";
        public static UInt32 DesiredAccess = 0x0010;
        public static int DelayToWait = 10;
    }
}
