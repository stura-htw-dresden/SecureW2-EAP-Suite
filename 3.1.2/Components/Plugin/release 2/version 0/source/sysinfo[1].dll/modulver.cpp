////////////////////////////////////////////////////////////////
// 1998 Microsoft Systems Journal
// If this code works, it was written by Paul DiLascia.
// If not, I don't know who wrote it.
//
// CModuleVersion provides an easy way to get version info
// for a module.(DLL or EXE).
//
#include "ModulVer.h"
#include <tchar.h>
#include <stdio.h>


CModuleVersion::CModuleVersion()
{
   m_pVersionInfo = NULL;           // raw version info data 
}

//////////////////
// Destroy: delete version info
//
CModuleVersion::~CModuleVersion()
{
   delete [] m_pVersionInfo;
}

//////////////////
// Get file version info for a given module
// Allocates storage for all info, fills "this" with
// VS_FIXEDFILEINFO, and sets codepage.
//
BOOL CModuleVersion::GetFileVersionInfo(LPCTSTR modulename)
{
   m_translation.charset = 1252;    // default = ANSI code page
   memset((VS_FIXEDFILEINFO*)this, 0, sizeof(VS_FIXEDFILEINFO));

   // fix: make sure the module is mapped into memory already!
   HINSTANCE hinst = LoadLibrary(modulename);
   if (!hinst)
      return FALSE;

   // get module handle
   TCHAR filename[_MAX_PATH];
   HMODULE hModule = ::GetModuleHandle(modulename);
   if (hModule==NULL && modulename!=NULL)
   {
	  FreeLibrary(hinst);
      return FALSE;
   }

   // get module file name
   DWORD len = GetModuleFileName(hModule, filename,
      sizeof(filename)/sizeof(filename[0]));
   if (len <= 0)
   {
	  FreeLibrary(hinst);
      return FALSE;
   }

   // read file version info
   DWORD dwDummyHandle; // will always be set to zero
   len = GetFileVersionInfoSize(filename, &dwDummyHandle);
   if (len <= 0)
   {
	  FreeLibrary(hinst);
      return FALSE;
   }

   m_pVersionInfo = new BYTE[len]; // allocate version info
   if (!::GetFileVersionInfo(filename, 0, len, m_pVersionInfo))
   {
	  FreeLibrary(hinst);
      return FALSE;
   }

   LPVOID lpvi;
   UINT iLen;
   if (!VerQueryValue(m_pVersionInfo, _T("\\"), &lpvi, &iLen))
   {
	  FreeLibrary(hinst);
      return FALSE;
   }

   // copy fixed info to myself, which am derived from VS_FIXEDFILEINFO
   *(VS_FIXEDFILEINFO*)this = *(VS_FIXEDFILEINFO*)lpvi;

   // Get translation info
   if (VerQueryValue(m_pVersionInfo,
      "\\VarFileInfo\\Translation", &lpvi, &iLen) && iLen >= 4) {
      m_translation = *(TRANSLATION*)lpvi;
      //TRACE("code page = %d\n", m_translation.charset);
   }

   BOOL result = dwSignature == VS_FFI_SIGNATURE;
   FreeLibrary(hinst);
   return result;
}

//////////////////
// Get string file info.
// Key name is something like "CompanyName".
// returns the value as a CString.
//
std::string CModuleVersion::GetValue(LPCTSTR lpKeyName)
{
   std::string sVal;
   if (m_pVersionInfo) {

      // To get a string value must pass query in the form
      //
      //    "\StringFileInfo\<langID><codepage>\keyname"
      //
      // where <langID><codepage> is the languageID concatenated with the
      // code page, in hex. Wow.
      //
      char buf[256];

      _stprintf(
         buf,
         _T("\\StringFileInfo\\%04x%04x\\%s"),      
         m_translation.langID,
         m_translation.charset,
         lpKeyName);

      std::string query(buf);

      LPCTSTR pVal;
      UINT iLenVal;
      if (VerQueryValue(m_pVersionInfo, (LPTSTR)(LPCTSTR)query.c_str(),
          (LPVOID*)&pVal, &iLenVal)) {

         sVal = pVal;
      }
   }
   return sVal;
}

// typedef for DllGetVersion proc
typedef HRESULT (CALLBACK* DLLGETVERSIONPROC)(DLLVERSIONINFO *);

/////////////////
// Get DLL Version by calling DLL's DllGetVersion proc
//
BOOL CModuleVersion::DllGetVersion(LPCTSTR modulename, DLLVERSIONINFO& dvi)
{
   HINSTANCE hinst = LoadLibrary(modulename);
   if (!hinst)
      return FALSE;

   // Must use GetProcAddress because the DLL might not implement 
   // DllGetVersion. Depending upon the DLL, the lack of implementation of the 
   // function may be a version marker in itself.
   //
   DLLGETVERSIONPROC pDllGetVersion =
      (DLLGETVERSIONPROC)GetProcAddress(hinst, _T("DllGetVersion"));

   if (!pDllGetVersion)
      return FALSE;

   memset(&dvi, 0, sizeof(dvi));        // clear
   dvi.cbSize = sizeof(dvi);            // set size for Windows

   HRESULT result = SUCCEEDED((*pDllGetVersion)(&dvi));
   FreeLibrary(hinst);
   return result;
}
