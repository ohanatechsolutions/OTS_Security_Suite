#define ProductName "OTS Security Suite"
#define ProductVersion "0.9.0"
#define PublisherName "Ohana Tech Solutions"
[Setup]
AppId={{D982EB60-E78C-48A1-98B1-B88D1CF71690}
AppName={#ProductName}
AppVersion={#ProductVersion}
AppPublisher={#PublisherName}
DefaultDirName={localappdata}\Programs\Ohana Tech Solutions\Security Suite
DefaultGroupName={#ProductName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\artifacts
OutputBaseFilename=OTS-Security-Suite-Setup-x64
SetupIconFile=AppIcon.ico
UninstallDisplayIcon={app}\OTSSecuritySuite.exe
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Files]
Source: "..\bundle\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{userdesktop}\OTS Security Suite"; Filename: "{app}\OTSSecuritySuite.exe"; WorkingDir: "{app}"; IconFilename: "{app}\OTSSecuritySuite.exe"; Tasks: desktopicon
Name: "{autoprograms}\OTS Security Suite"; Filename: "{app}\OTSSecuritySuite.exe"; WorkingDir: "{app}"; IconFilename: "{app}\OTSSecuritySuite.exe"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: checkedonce

[Registry]
Root: HKCU; Subkey: "Software\Classes\ots-security"; ValueType: string; ValueName: ""; ValueData: "URL:OTS Security Suite"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\ots-security"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCU; Subkey: "Software\Classes\ots-security\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\OTSSecuritySuite.exe,0"
Root: HKCU; Subkey: "Software\Classes\ots-security\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\OTSSecuritySuite.exe"" ""%1"""

[Run]
Filename: "{app}\OTSSecuritySuite.exe"; Description: "Launch OTS Security Suite"; Flags: nowait postinstall skipifsilent
