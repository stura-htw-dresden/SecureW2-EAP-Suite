Name "x18sysinfoV0.1.dll Demo"
OutFile "x18sysinfoV0.1.dll Demo.exe"
DirShow hide
ShowInstDetails show

!macro GetSysVer VALUE
	Push ${VALUE}
	CallInstDLL "$R0" GetSystemVersionValue
	Pop $9
	DetailPrint 'GetSystemVersionValue: ${VALUE}: $9'
!macroend

!macro GetDllVer PATH PART DISPLAY
	Push ${PATH}
	Push ${PART}
	CallInstDLL "$R0" GetDllVersion
	Pop $9
	StrCmp $9 '' 0 skip${DISPLAY}${PART}
	StrCpy $9 'File does not support DllGetVersion'
	skip${DISPLAY}${PART}:
	DetailPrint 'GetDllVersion: ${DISPLAY}: ${PART}: $9'
!macroend

!macro GetFileVer PATH DISPLAY
	Push ${PATH}
	CallInstDLL "$R0" GetFileVersion
	Pop $9
	DetailPrint 'GetFileVersion: ${DISPLAY}: $9'
!macroend

!macro GetFileVerPart PATH PART DISPLAY
	Push ${PATH}
	Push ${PART}
	CallInstDLL "$R0" GetFileVersionValue
	Pop $9
	DetailPrint '${DISPLAY}: ${PART}: $9'
!macroend

; ----------------------------------------------------------------------------
; Always carry out these commands on install.
; ----------------------------------------------------------------------------
Section ""
  SetOutPath $TEMP
  GetTempFileName $R0
  File /oname=$R0 "x18sysinfoV0.1.dll"
	!insertmacro GetSysVer 'MajorVersion'
	!insertmacro GetSysVer 'MinorVersion'
	!insertmacro GetSysVer 'BuildNumber'
	!insertmacro GetSysVer 'CsdVersion'
	!insertmacro GetSysVer 'ServicePackMajorVersion'
	!insertmacro GetSysVer 'ServicePackMinorVersion'
	!insertmacro GetSysVer 'ProductType'
	!insertmacro GetSysVer 'InstalledComponents'
	!insertmacro GetDllVer 'c:\winnt\system32\batmeter.dll' 'Version' 'batmeter.dll'
	!insertmacro GetDllVer 'c:\winnt\system32\batmeter.dll' 'Build' 'batmeter.dll'
	!insertmacro GetDllVer 'c:\winnt\system32\batmeter.dll' 'Platform' 'batmeter.dll'
	!insertmacro GetDllVer 'c:\winnt\system32\comctl32.dll' 'Version' 'comctl32.dll'
	!insertmacro GetDllVer 'c:\winnt\system32\comctl32.dll' 'Build' 'comctl32.dll'
	!insertmacro GetDllVer 'c:\winnt\system32\comctl32.dll' 'Platform' 'comctl32.dll'
	!insertmacro GetFileVer 'c:\winnt\system32\batmeter.dll' 'batmeter.dll'
	!insertmacro GetFileVer 'c:\winnt\system32\comctl32.dll' 'comctl32.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\batmeter.dll' 'CompanyName' 'batmeter.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\batmeter.dll' 'FileDescription' 'batmeter.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\batmeter.dll' 'FileVersion' 'batmeter.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\batmeter.dll' 'InternalName' 'batmeter.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\batmeter.dll' 'LegalCopyright' 'batmeter.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\batmeter.dll' 'OriginalFilename' 'batmeter.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\batmeter.dll' 'ProductName' 'batmeter.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\batmeter.dll' 'ProductVersion' 'batmeter.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\comctl32.dll' 'CompanyName' 'comctl32.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\comctl32.dll' 'FileDescription' 'comctl32.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\comctl32.dll' 'FileVersion' 'comctl32.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\comctl32.dll' 'InternalName' 'comctl32.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\comctl32.dll' 'LegalCopyright' 'comctl32.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\comctl32.dll' 'OriginalFilename' 'comctl32.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\comctl32.dll' 'ProductName' 'comctl32.dll'
	!insertmacro GetFileVerPart 'c:\winnt\system32\comctl32.dll' 'ProductVersion' 'comctl32.dll'
	Delete $R0
SectionEnd
