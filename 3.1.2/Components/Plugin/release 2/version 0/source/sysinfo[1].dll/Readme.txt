

x18sysinfoV0.1.zip
-------------------

Extraction of arbitrary version strings from files is possible thanks to a
1998 Microsoft Systems Journal article by Paul DiLascia.


What The Hell Is This?
----------------------

This is an extension dll for the Nullsoft Installation System (NSIS) that can
be used to find out version information about the operating system or dlls and
files on the computer. It can retrieve things like the service pack number 
installed, or the build number of Windows, or the Legal Copyright string inside
a file version descriptor, and so on.

Most of the code is based on information found in the Microsoft Knowledge Base
and the MSDN Platform SDK documentation. An extra large chunk of it is based
completely, almost verbatim, on code by Paul DiLascia in the 1998 Microsoft
Systems Journal.

Feel free to send comments/suggestions/bug fixes/hate mail/biscuits to 
ximon_eighteen@3b2.com or ximon_eighteen@hotmail.com. I'm on MSN Messenger at 
the hotmail address for those in desperate need of badgering me about 
something.

As long as you don't violate any nullsoft agreement that might be binding on
an extension DLL for their NSIS product as far as I'm concerned you can do
absolutely anything with this code, claim as your own if you like although
that would be a bit low.

I'll answer any questions that I can, but I'm not responsible if this fouls
up your system, use this at your own risk. If something does go wrong I'll do
what I can to help, but I think this is highly unlikely ;-)

---

Sunjammer/X - Ximon Eighteen
Programmer @ Advent Publishing Systems


Version History :
-----------------

Version 0.1, minor bug fix, 27th August 2002 by Ximon Eighteen.
  GetFileVersion wouldn't work unless DllGetVersion had been called first.
Version 0.0, first alpha, 13th June 2002 by Ximon Eighteen.

Distribution :
--------------

  - x18sysinfoV0.0.dll
  - x18sysinfoV0.0.dll Demo.exe
  - readme.txt
  - sysinfo.cpp
  - nsisapi.h
  - winerror.h
  - winerror.cpp
  - exdll.cpp
  - modulver.cpp
  - modulver.h
  - Visual C++ 6.0 project file (.dsp) [ release & debug configurations ]


  The code is based on the exdll project that shipped with 0.98 of the NSIS 
  distro. Building the project should result in a .dll file that you can then 
  use with the CallInstDLL NSIS scripting command.


Known Bugs/Issues :
-------------------

  - The arbitrary strings that can be stored in a file version chunk cannot
    be walked. Therefore you need to know the name of the value you want in
    advance. This feature will be added soon I expect although it's only
    really of use to someone viewing all version information rather than
    checking for a certain level of conformance with expectation. Some example
    strings are :-

      - CompanyName
      - FileDescription
      - FileVersion
      - InternalName
      - LegalCopyright
      - OriginalFilename
      - ProductName
      - ProductVersion

    This is the information that you would typically see in the Version tab
    in the Windows 2000 file properties window.

  - Some information available from the system that can be obtained from
    the system is NOT available from this DLL. This includes the following
    (can be included if anyone *really* needs it, as it is this DLL provides
    far more than anything else I've seen for a while) :-

      - VS_FF_DEBUG         The file contains debugging information or is 
                            compiled with debugging features enabled
      - VS_FF_INFOINFERRED  The file has been modified and is not identical 
                            to the original shipping file of the same version 
                            number
      - VS_FF_PRERELEASE    The file is a development version, not a 
                            commercially released product.
      - VS_FF_PRIVATEBUILD  The file was not built using standard release 
                            procedures
      - VS_FF_SPECIALBUILD  The file was built by the original company using 
                            standard release procedures but is a variation of 
                            the normal file of the same version number

      - File OS, the operating system the file is flagged for... can be
        DOS, NT, WINDOWS 16, WINDOWS 32, OS2 16, OS2 32, PM 16, PM 32 or
        UNKNOWN
 
      - File Type, can be APP, DLL, Device Driver, Font, VxD, Static Lib
      - Driver Sub Types
      - Font Sub Types

      - Creation Date

    [*Note: Just because the system says provides a means for obtaining this
     information does NOT necessarily mean that a file will contain it*]

  - No other known issues.


Function Level Docs : 
---------------------

  See the demonstration .nsi file for a working example of every call that this
  DLL supports. 

  [*Note: If anyone has any idea why the Service Pack description is called
   the CsdVersion (this name is the internal windows name) I'd love to know*]

  [*Note: The InstalledComponents is rather special. I've no idea how often
   you'll see these strings set. What you get back is a number that is a
   combination of flags, here are some that I know, some of which are NOT 
   documented that I can find so I don't know what they mean either ;-)

     - VER_SERVER_NT                       0x80000000
     - VER_WORKSTATION_NT                  0x40000000
     - VER_SUITE_SMALLBUSINESS             0x00000001
     - VER_SUITE_ENTERPRISE                0x00000002 // Windows 2000 Advanced Server
     - VER_SUITE_BACKOFFICE                0x00000004
     - VER_SUITE_COMMUNICATIONS            0x00000008
     - VER_SUITE_TERMINAL                  0x00000010 // Terminal Services
     - VER_SUITE_SMALLBUSINESS_RESTRICTED  0x00000020
     - VER_SUITE_EMBEDDEDNT                0x00000040
     - VER_SUITE_DATACENTER                0x00000080
     - VER_SUITE_SINGLEUSERTS              0x00000100
     - VER_SUITE_PERSONAL                  0x00000200 // Windows XP Home Edition
     - VER_SUITE_BLADE                     0x00000400
  
  *]

    GetSystemVersionValue
        Expects a value name on the stack. Possible values are :
            - MajorVersion
            - MinorVersion
            - BuildNumber
            - CsdVersion                (service pack level description)
            - ServicePackMajorVersion
            - ServicePackMinorVersion
            - ProductType               (workstation, domain controller or server)
            - InstalledComponents       (bit mask of installed component ids)
        A string representation of a number is placed on the stack unless 
        except as stated above for particular value names. In the event of 
        failure a single empty string is placed on the stack.

    GetDllVersion
        Expects a file path on the stack AND a string, one of 'Version',
        'Build' or 'Platform'. The requested value will be pushed onto the
        stack. In the event of failure a single empty string will be pushed 
        onto the stack.
    GetFileVersion
        Expects a file path on the stack. Returns a string containing four
        components of the version number in the form a.b.c.d (where a, b, c
        and d are integer numbers). In the event of failure a single empty
        string will be pushed onto the stack.
    GetFileVersionValue
        Expects a file path AND an arbitrary string. The file version 
        information record will be searched for the requested item of
        information by name. If found it will be pushed onto the stack,
        otherwise an empty string will be pushed on instead.
