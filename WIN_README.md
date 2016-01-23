- Have Python 2.7.11 installed. (be sure to stick to a 32 bit Python environment for all of the module and Python installations to avoid errors.)

- Download and install Yara

-- https://b161268c3bf5a87bc67309e7c870820f5f39f672.googledrive.com/host/0BznOMqZ9f3VUek8yN3VvSGdhRFU/yara-python-3.4.0.win32-py2.7.exe

- Ensure the libyara.dll file provided by the above yara installer is copied into a directory which is added to your windows PATH environment variable.

- PIP install python-magic, pip.exe install python-magic

-- Read here, https://github.com/ahupp/python-magic#dependencies , it wants DLL files from the Windows installation for "File", the installer is found here, http://downloads.sourceforge.net/gnuwin32/file-5.03-setup.exe. Then in the script, when magic is called, it needs the path to the magic executable installed from the above installer, so ensure that the above installer installed a program to the following path, C:\Program Files (x86)\GnuWin32. Under that directory there is a file you need to note the path of. The full path to it should be, C:\Program Files (x86)\GnuWin32\share\misc\magic. Make sure that file exists in that.

- PIP install oletools, pip.exe install oletools

- Download and install swftools for Windows, install as Administrator, http://www.swftools.org/swftools-0.9.0.exe
-- Add the SWFTools installation path to your PATH Windows environment variable.
