OutFile sysinfo.exe
PluginDir .
Section
  sysinfo::GetSystemVersionValue 'MajorVersion'
  sysinfo::GetSystemVersionValue 'MinorVersion'
  sysinfo::GetSystemVersionValue 'BuildNumber'
  sysinfo::GetSystemVersionValue 'CsdVersion'
  sysinfo::GetSystemVersionValue 'ServicePackMajorVersion'
  sysinfo::GetSystemVersionValue 'ServicePackMinorVersion'
  sysinfo::GetSystemVersionValue 'ProductType'
  sysinfo::GetSystemVersionValue 'InstalledComponents'
  Pop $7
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
  MessageBox MB_OK|MB_ICONINFORMATION 'Major: $0$\nMinor: $1$\nBuild: $2$\nCsd: $3$\nSP Major: $4$\nSP Minor: $5$\nType: $6$\nComp: $7$\n'
  sysinfo::GetDllVersion 'Version' '$WINDIR\system32\batmeter.dll'
  sysinfo::GetDllVersion 'Build' '$WINDIR\system32\batmeter.dll'
  sysinfo::GetDllVersion 'Platform' '$WINDIR\system32\batmeter.dll'
  sysinfo::GetDllVersion 'Version' '$WINDIR\system32\comctl32.dll'
  sysinfo::GetDllVersion 'Build' '$WINDIR\system32\comctl32.dll'
  sysinfo::GetDllVersion 'Platform' '$WINDIR\system32\comctl32.dll'
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
  MessageBox MB_OK|MB_ICONINFORMATION 'Batmeter Version: $0$\nBatmeter Build: $1$\nBatmeter Platform: $2$\nComCtl32 Version: $3$\nComCtl32 Build: $4$\nComCtl32 Version: $5'
  sysinfo::GetFileVersion '$WINDIR\system32\batmeter.dll'
  sysinfo::GetFileVersion '$WINDIR\system32\comctl32.dll'
  Pop $1
  Pop $0
  MessageBox MB_OK|MB_ICONINFORMATION 'Batmeter FileVersion: $0$\nComCtl32 FileVersion: $1'
  sysinfo::GetFileVersionValue 'CompanyName' '$WINDIR\system32\batmeter.dll' 
  sysinfo::GetFileVersionValue 'FileDescription' '$WINDIR\system32\batmeter.dll'
  sysinfo::GetFileVersionValue 'FileVersion' '$WINDIR\system32\batmeter.dll'
  sysinfo::GetFileVersionValue 'InternalName' '$WINDIR\system32\batmeter.dll'
  sysinfo::GetFileVersionValue 'LegalCopyright' '$WINDIR\system32\batmeter.dll'
  sysinfo::GetFileVersionValue 'OriginalFilename' '$WINDIR\system32\batmeter.dll'
  sysinfo::GetFileVersionValue 'ProductName' '$WINDIR\system32\batmeter.dll'
  sysinfo::GetFileVersionValue 'ProductVersion' '$WINDIR\system32\batmeter.dll'
  Pop $7
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
  MessageBox MB_OK|MB_ICONINFORMATION 'Batmeter Company: $0$\Batmeter FileDesc: $1$\Batmeter FileVer: $2$\Batmeter Name: $3$\Batmeter Legal: $4$\Batmeter OrgName: $5$\Batmeter Product: $6$\Batmeter ProdVer: $7$\n'
  sysinfo::GetFileVersionValue 'CompanyName' '$WINDIR\system32\comctl32.dll' 
  sysinfo::GetFileVersionValue 'FileDescription' '$WINDIR\system32\comctl32.dll'
  sysinfo::GetFileVersionValue 'FileVersion' '$WINDIR\system32\comctl32.dll'
  sysinfo::GetFileVersionValue 'InternalName' '$WINDIR\system32\comctl32.dll'
  sysinfo::GetFileVersionValue 'LegalCopyright' '$WINDIR\system32\comctl32.dll'
  sysinfo::GetFileVersionValue 'OriginalFilename' '$WINDIR\system32\comctl32.dll'
  sysinfo::GetFileVersionValue 'ProductName' '$WINDIR\system32\comctl32.dll'
  sysinfo::GetFileVersionValue 'ProductVersion' '$WINDIR\system32\comctl32.dll'
  Pop $7
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
  MessageBox MB_OK|MB_ICONINFORMATION 'ComCtrl32 Company: $0$\nComCtrl32 FileDesc: $1$\nComCtrl32 FileVer: $2$\nComCtrl32 Name: $3$\nComCtrl32 Legal: $4$\nComCtrl32 OrgName: $5$\nComCtrl32 Product: $6$\nComCtrl32 ProdVer: $7$\n'
SectionEnd