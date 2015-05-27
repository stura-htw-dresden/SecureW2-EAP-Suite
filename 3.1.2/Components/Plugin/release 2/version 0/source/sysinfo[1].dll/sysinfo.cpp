

/*
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

    Limitations:
        - Cannot walk version strings in a block, can only ask for them by name
        - Does not return all of the values from the VS_FIXEDFILEINFO block
*/


#include "nsisapi.h"
#include <stdlib.h>
#include "modulver.h"


OSVERSIONINFOEX gSysInfo;
bool            gQueried  = false;
bool            gExtended = false;


void PushNumber(int number)
{
    char buf[25];
    itoa(number,buf,10);
    pushstring(buf);
}

void Query(void)
{
    if (!gQueried)
    {
        gExtended = false;
        
        ZeroMemory(&gSysInfo,sizeof(OSVERSIONINFOEX));
        gSysInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        
        if (GetVersionEx((OSVERSIONINFO*)&gSysInfo))
        {
            gExtended = true;
        }
        else
        {
            gSysInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
            GetVersionEx((OSVERSIONINFO*)&gSysInfo);
        }

        gQueried = true;
    }
}

extern "C" void __declspec(dllexport) GetSystemVersionValue(HWND,int string_size,char*,stack_t** stacktop)
{
    char valueName[256];

    g_stacktop   = stacktop;
	g_stringsize = string_size;
    
    if (0 == popstring(valueName))
    {
        Query();

        if      (0 == stricmp(valueName,"MajorVersion"))                PushNumber(gSysInfo.dwMajorVersion);
        else if (0 == stricmp(valueName,"MinorVersion"))                PushNumber(gSysInfo.dwMinorVersion);
        else if (0 == stricmp(valueName,"BuildNumber"))                 PushNumber(gSysInfo.dwBuildNumber);
        else if (0 == stricmp(valueName,"CsdVersion"))                  pushstring(gSysInfo.szCSDVersion);
        else if (gExtended)
        {
            if (0 == stricmp(valueName,"ServicePackMajorVersion"))      PushNumber(gSysInfo.wServicePackMajor);
            else if (0 == stricmp(valueName,"ServicePackMinorVersion")) PushNumber(gSysInfo.wServicePackMinor);
            else if (0 == stricmp(valueName,"ProductType"))
            {
                switch (gSysInfo.wProductType)
                {
                    case VER_NT_WORKSTATION:       pushstring("Workstation");       break;
                    case VER_NT_DOMAIN_CONTROLLER: pushstring("Domain Controller"); break;
                    case VER_NT_SERVER:            pushstring("Server");            break;
                    default:                       pushstring("");                  break;
                }
            }
            else if (0 == stricmp(valueName,"InstalledComponents"))
            {
                /*
                #define VER_SERVER_NT                       0x80000000
                #define VER_WORKSTATION_NT                  0x40000000
                #define VER_SUITE_SMALLBUSINESS             0x00000001
                #define VER_SUITE_ENTERPRISE                0x00000002 // Windows 2000 Advanced Server
                #define VER_SUITE_BACKOFFICE                0x00000004
                #define VER_SUITE_COMMUNICATIONS            0x00000008
                #define VER_SUITE_TERMINAL                  0x00000010
                #define VER_SUITE_SMALLBUSINESS_RESTRICTED  0x00000020
                #define VER_SUITE_EMBEDDEDNT                0x00000040
                #define VER_SUITE_DATACENTER                0x00000080
                #define VER_SUITE_SINGLEUSERTS              0x00000100
                #define VER_SUITE_PERSONAL                  0x00000200 // Windows XP Home Edition
                #define VER_SUITE_BLADE                     0x00000400
                */

                PushNumber(gSysInfo.wSuiteMask);
            }
            else if (0 == stricmp(valueName,""))
            {
            }
        }
        else
            pushstring("");
    }
}

// expects user to push the file path onto the stack 
extern "C" void __declspec(dllexport) GetFileVersion(HWND,int string_size,char*,stack_t** stacktop)
{
    char filepath[256];
    
    g_stacktop   = stacktop;
	g_stringsize = string_size;

    if (0 == popstring(filepath))
    {
        CModuleVersion ver;
        if (ver.GetFileVersionInfo(filepath))
        {
            char buf[256];
            sprintf(buf,"%d.%d.%d.%d",
                HIWORD(ver.dwFileVersionMS), LOWORD(ver.dwFileVersionMS),
                HIWORD(ver.dwFileVersionLS), LOWORD(ver.dwFileVersionLS));

            pushstring(buf);
            return;
        }
    }

    pushstring("");
}

// expects user to push the file path onto the stack
// if the file supports DllGetVersion 3 strings will be pushed onto the stack
// otherwise a single empty string will be pushed onto the stack
extern "C" void __declspec(dllexport) GetDllVersion(HWND,int string_size,char*,stack_t** stacktop)
{
    char filepath[256];
    char key[256];

    g_stacktop   = stacktop;
	g_stringsize = string_size;
    
    if (0 == popstring(key) && 0 == popstring(filepath))
    {
        CModuleVersion ver;
        DLLVERSIONINFO dvi;

        if (ver.DllGetVersion(filepath,dvi))
        {
            char buf[256];
            buf[0] = '\0';

            if      (0 == stricmp(key,"Version"))  sprintf(buf,"%d.%02d",dvi.dwMajorVersion,dvi.dwMinorVersion);
            else if (0 == stricmp(key,"Build"))    sprintf(buf,"%d",dvi.dwBuildNumber);
            else if (0 == stricmp(key,"Platform"))
            {
                if      (DLLVER_PLATFORM_WINDOWS == dvi.dwPlatformID) strcpy(buf,"Windows");
                else if (DLLVER_PLATFORM_NT      == dvi.dwPlatformID) strcpy(buf,"Windows NT");
            }

            pushstring(buf);
            return;
        }
    }

    pushstring("");
}

// expects user to push onto the stack the file path followed by the desired string
extern "C" void __declspec(dllexport) GetFileVersionValue(HWND,int string_size,char*,stack_t** stacktop)
{
    char filepath[256];
    char key[256];

    g_stacktop   = stacktop;
	g_stringsize = string_size;
    
    if (0 == popstring(key) && 0 == popstring(filepath))
    {
        CModuleVersion ver;
        if (ver.GetFileVersionInfo(filepath))
        {
            pushstring((char*)(ver.GetValue(key).c_str()));
            return;
        }
    }

    pushstring("");
}
