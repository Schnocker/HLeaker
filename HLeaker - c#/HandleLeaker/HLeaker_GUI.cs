using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HandleLeaker
{
    public partial class HLeaker_GUI : Form
    {
        IntPtr hProcess = IntPtr.Zero;
        public HLeaker_GUI(IntPtr hProcess)
        {
            InitializeComponent();
            this.hProcess = hProcess;
        }

        private void HLeaker_GUI_Load(object sender, EventArgs e)
        {
        }
    }
}
