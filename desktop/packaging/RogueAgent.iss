; Inno Setup script for the Rogue Agent Windows installer.
; Build after scripts/desktop/package-windows.mjs:
;   iscc /DAppVersion=6.4.0 /DSourceDir=..\..\out\RogueAgent-win-x64 /O..\..\out RogueAgent.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\out\RogueAgent-win-x64"
#endif

[Setup]
AppId={{6B1C9F1E-4E2B-4C53-9B2E-5D8C6E2A7F41}
AppName=Rogue Agent
AppVersion={#AppVersion}
AppVerName=Rogue Agent {#AppVersion}
AppPublisher=Rogue Agent
AppPublisherURL=https://github.com/CliveWetherington-1994/Rogue-Agent
AppSupportURL=https://github.com/CliveWetherington-1994/Rogue-Agent/issues
DefaultDirName={localappdata}\Programs\Rogue Agent
DefaultGroupName=Rogue Agent
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputBaseFilename=RogueAgent-{#AppVersion}-Setup-x64
SetupIconFile=..\launcher\assets\rogue-agent.ico
UninstallDisplayIcon={app}\RogueAgent.exe
; About 1 GB with the bundled Ghidra and JDK: multithreaded LZMA2 keeps the
; build to a few minutes.
Compression=lzma2/max
SolidCompression=yes
LZMAUseSeparateProcess=yes
LZMANumBlockThreads=4
WizardStyle=modern
LicenseFile=..\..\LICENSE
ChangesAssociations=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "openwith"; Description: "Offer Rogue Agent in the ""Open with"" menu for programs and libraries"; GroupDescription: "Integration:"

[InstallDelete]
; An upgrade replaces these folders whole, so no file from an older Ghidra,
; JDK or engine lingers beside the new one.
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\ghidra"
Type: filesandordirs; Name: "{app}\jdk"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Rogue Agent"; Filename: "{app}\RogueAgent.exe"
Name: "{group}\Uninstall Rogue Agent"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Rogue Agent"; Filename: "{app}\RogueAgent.exe"; Tasks: desktopicon

[Registry]
; "Open with" registration only: never changes the default handler of any type.
Root: HKA; Subkey: "Software\Classes\Applications\RogueAgent.exe"; ValueType: string; ValueName: "FriendlyAppName"; ValueData: "Rogue Agent"; Flags: uninsdeletekey; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\Applications\RogueAgent.exe\shell\open\command"; ValueType: string; ValueData: """{app}\RogueAgent.exe"" ""%1"""; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\Applications\RogueAgent.exe\SupportedTypes"; ValueType: string; ValueName: ".exe"; ValueData: ""; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\Applications\RogueAgent.exe\SupportedTypes"; ValueType: string; ValueName: ".dll"; ValueData: ""; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\Applications\RogueAgent.exe\SupportedTypes"; ValueType: string; ValueName: ".sys"; ValueData: ""; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\.dll\OpenWithList\RogueAgent.exe"; ValueType: none; Flags: uninsdeletekey; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\.sys\OpenWithList\RogueAgent.exe"; ValueType: none; Flags: uninsdeletekey; Tasks: openwith

[Run]
Filename: "{app}\RogueAgent.exe"; Description: "{cm:LaunchProgram,Rogue Agent}"; Flags: nowait postinstall skipifsilent

[Code]
function WebView2Installed(): Boolean;
var
  Version: String;
begin
  Result :=
    RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) or
    RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) or
    RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version);
  Result := Result and (Version <> '') and (Version <> '0.0.0.0');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ErrorCode: Integer;
begin
  if (CurStep = ssPostInstall) and (not WizardSilent()) and (not WebView2Installed()) then
    if MsgBox('Rogue Agent draws its window with the Microsoft Edge WebView2 Runtime, which was not found.' + #13#10#13#10 +
              'Open the download page now? (Without it, Rogue Agent offers to run in your web browser.)',
              mbConfirmation, MB_YESNO) = IDYES then
      ShellExec('open', 'https://developer.microsoft.com/microsoft-edge/webview2/', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
end;
