#ifndef AgentVersion
  #define AgentVersion "0.1.0"
#endif

#define AgentName "Telesec Network Agent"
#define AgentExe "TelesecAgent.exe"
#define TrayExe "TelesecTray.exe"
#define ServiceName "TelesecNetworkAgent"

[Setup]
AppId={{19BE581B-1D21-4BEA-9CCB-DF37D02BFD72}
AppName={#AgentName}
AppVersion={#AgentVersion}
AppPublisher=Telesec
AppPublisherURL=https://telesec.local
DefaultDirName={autopf}\Telesec\NetworkAgent
DefaultGroupName=Telesec
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
OutputDir=..\dist\installer
OutputBaseFilename=Telesec-Network-Agent-Setup-{#AgentVersion}
UninstallDisplayName={#AgentName}
SetupLogging=yes
CloseApplications=yes
RestartApplications=no

[Files]
Source: "..\dist\agent\{#AgentExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\agent\{#TrayExe}"; DestDir: "{app}"; Flags: ignoreversion
#ifdef IncludeOemDependencies
Source: "dependencies\nmap-oem.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
#endif

[Icons]
Name: "{group}\Telesec Network Agent"; Filename: "{app}\{#TrayExe}"; WorkingDir: "{app}"; IconFilename: "{app}\{#TrayExe}"; Comment: "Show Telesec network agent status"

[Run]
#ifndef IncludeOemDependencies
Filename: "https://nmap.org/download.html"; Description: "Install Nmap and Npcap for network discovery"; Flags: shellexec nowait postinstall skipifsilent; Check: ScannerDependenciesMissing
#endif
Filename: "{app}\{#AgentExe}"; Parameters: "service install"; StatusMsg: "Registering the Telesec service..."; Flags: runhidden waituntilterminated; BeforeInstall: PrepareAgentData
Filename: "{app}\{#AgentExe}"; Parameters: "service start"; StatusMsg: "Connecting the Telesec agent..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#TrayExe}"; Description: "Show Telesec agent status in the notification area"; Flags: nowait postinstall skipifsilent

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "TelesecNetworkAgentTray"; ValueData: """{app}\{#TrayExe}"""; Flags: uninsdeletevalue

[UninstallRun]
Filename: "{app}\{#TrayExe}"; Parameters: "--stop"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "StopTelesecTray"
Filename: "{app}\{#AgentExe}"; Parameters: "service stop"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "StopTelesecService"
Filename: "{app}\{#AgentExe}"; Parameters: "service remove"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "RemoveTelesecService"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\Telesec\NetworkAgent"
Type: dirifempty; Name: "{commonappdata}\Telesec"
Type: filesandordirs; Name: "{app}"
Type: dirifempty; Name: "{autopf}\Telesec"

[Code]
var
  EnrollmentPage: TInputQueryWizardPage;

function FreshEnrollmentRequested: Boolean;
var
  Value: String;
begin
  Value := Lowercase(Trim(ExpandConstant('{param:RESETAGENTDATA|0}')));
  Result := (Value = '1') or (Value = 'true') or (Value = 'yes');
end;

function ExistingEnrollment: Boolean;
begin
  Result := (not FreshEnrollmentRequested) and FileExists(ExpandConstant('{commonappdata}\Telesec\NetworkAgent\identity\identity.json'));
end;

function NpcapInstalled: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap');
end;

function NmapInstalled: Boolean;
begin
  Result :=
    FileExists(ExpandConstant('{pf}\Nmap\nmap.exe')) or
    FileExists(ExpandConstant('{pf32}\Nmap\nmap.exe'));
end;

function ScannerDependenciesMissing: Boolean;
begin
  Result := (not NmapInstalled) or (not NpcapInstalled);
end;

function AllowedServerUrl(Value: String): Boolean;
var
  Normalized: String;
begin
  Normalized := Lowercase(Trim(Value));
  Result :=
    (Pos('https://', Normalized) = 1) or
    (Pos('http://127.0.0.1', Normalized) = 1) or
    (Pos('http://localhost', Normalized) = 1) or
    (Pos('http://[::1]', Normalized) = 1);
end;

function JsonEscape(Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '"', '\"', True);
  StringChangeEx(Result, #13, '\r', True);
  StringChangeEx(Result, #10, '\n', True);
end;

procedure InitializeWizard;
begin
  EnrollmentPage := CreateInputQueryPage(
    wpSelectDir,
    'Connect to Telesec',
    'Enter the control server enrollment details.',
    'Create a one-time token in the Telesec dashboard. HTTPS is required except for a server running on this computer.'
  );
  EnrollmentPage.Add('Server URL:', False);
  EnrollmentPage.Add('One-time enrollment token:', True);
  EnrollmentPage.Values[0] := ExpandConstant('{param:SERVERURL|http://127.0.0.1:8000}');
  EnrollmentPage.Values[1] := ExpandConstant('{param:ENROLLMENTTOKEN|}');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := ExistingEnrollment and (PageID = EnrollmentPage.ID);
end;

function ValidateEnrollment: String;
begin
  Result := '';
  if ExistingEnrollment then
    Exit;
  if not AllowedServerUrl(EnrollmentPage.Values[0]) then
  begin
    Result := 'Enter an HTTPS Telesec server URL. HTTP is allowed only for localhost.';
    Exit;
  end;
  if Length(Trim(EnrollmentPage.Values[1])) < 32 then
    Result := 'Enter a valid one-time enrollment token from the Telesec dashboard.';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Problem: String;
begin
  Result := True;
  if CurPageID = EnrollmentPage.ID then
  begin
    Problem := ValidateEnrollment;
    if Problem <> '' then
    begin
      MsgBox(Problem, mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure WriteBootstrap; forward;
procedure ProtectAgentData; forward;
procedure RemoveAgentData; forward;
procedure PrepareAgentData; forward;
procedure GrantPrivateDataAccess(RootDirectory: String); forward;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ExistingAgent: String;
  ExistingTray: String;
  ResultCode: Integer;
begin
  Result := ValidateEnrollment;
  if Result <> '' then
    Exit;
  if ScannerDependenciesMissing and (not WizardSilent) then
  begin
#ifdef IncludeOemDependencies
    MsgBox(
      'Nmap or Npcap is missing. Telesec Setup will now install both scanner dependencies automatically.',
      mbInformation,
      MB_OK
    );
#else
    MsgBox(
      'Nmap or Npcap is missing. This development package cannot redistribute them. The official Nmap Windows download page will open when Setup finishes; its installer includes Npcap.',
      mbInformation,
      MB_OK
    );
#endif
  end;
  ExistingTray := ExpandConstant('{app}\{#TrayExe}');
  if FileExists(ExistingTray) then
  begin
    Exec(
      ExistingTray,
      '--stop',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    );
  end;
  ExistingAgent := ExpandConstant('{app}\{#AgentExe}');
  if FileExists(ExistingAgent) then
  begin
    Exec(
      ExistingAgent,
      'service stop',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    );
    if FreshEnrollmentRequested then
    begin
      Exec(
        ExistingAgent,
        'service remove',
        '',
        SW_HIDE,
        ewWaitUntilTerminated,
        ResultCode
      );
    end;
  end;
  Exec(
    ExpandConstant('{sys}\sc.exe'),
    'stop {#ServiceName}',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if FreshEnrollmentRequested then
  begin
    Exec(
      ExpandConstant('{sys}\sc.exe'),
      'delete {#ServiceName}',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    );
  end;
  Sleep(1000);
end;

#ifdef IncludeOemDependencies
procedure InstallScannerDependencies;
var
  ResultCode: Integer;
begin
  if not ScannerDependenciesMissing then
    Exit;
  WizardForm.StatusLabel.Caption := 'Installing Nmap and the Npcap packet driver...';
  if not Exec(
    ExpandConstant('{tmp}\nmap-oem.exe'),
    '/S /ZENMAP=NO /NDIFF=NO',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
    RaiseException('Unable to start the licensed Nmap installer.');
  if ResultCode <> 0 then
    RaiseException(Format('Nmap installation failed with exit code %d.', [ResultCode]));
  if ScannerDependenciesMissing then
    RaiseException('Nmap or Npcap is still missing after dependency installation.');
end;
#endif

procedure GrantPrivateDataAccess(RootDirectory: String);
var
  ResultCode: Integer;
begin
  ForceDirectories(RootDirectory);
  Exec(
    ExpandConstant('{sys}\takeown.exe'),
    '/F "' + RootDirectory + '" /A /R /D Y',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to take ownership of the Telesec data directory.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + RootDirectory + '" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to grant direct access to the Telesec data directory.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + RootDirectory + '" /grant "*S-1-5-18:F" "*S-1-5-32-544:F" /T /C',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to grant file access to the Telesec data directory.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + RootDirectory + '" /grant "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to grant inherited access to the Telesec data directory.');
end;

procedure WriteBootstrap;
var
  ConfigDirectory: String;
  ConfigPath: String;
  RootDirectory: String;
  ResultCode: Integer;
  BootstrapParameters: String;
begin
  if ExistingEnrollment then
  begin
    Log('Telesec bootstrap unchanged because an existing enrollment is present.');
    Exit;
  end;
  RootDirectory := ExpandConstant('{commonappdata}\Telesec\NetworkAgent');
  ConfigDirectory := ExpandConstant('{commonappdata}\Telesec\NetworkAgent\config');
  ConfigPath := ConfigDirectory + '\bootstrap.json';
  Log('Writing Telesec bootstrap configuration to ' + ConfigPath);
  ForceDirectories(ConfigDirectory);
  GrantPrivateDataAccess(RootDirectory);
  if FileExists(ConfigPath) and (not DeleteFile(ConfigPath)) then
    RaiseException('Unable to replace the Telesec bootstrap configuration.');
  BootstrapParameters := 'bootstrap --server-url "' + Trim(EnrollmentPage.Values[0]) + '" --enrollment-token "' + Trim(EnrollmentPage.Values[1]) + '"';
  if not Exec(
    ExpandConstant('{app}\{#AgentExe}'),
    BootstrapParameters,
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
    RaiseException('Unable to start the Telesec bootstrap writer.');
  if ResultCode <> 0 then
    RaiseException('Unable to write the Telesec bootstrap configuration.');
  Log('Telesec bootstrap configuration written.');
end;

procedure RemoveAgentData;
var
  RootDirectory: String;
begin
  RootDirectory := ExpandConstant('{commonappdata}\Telesec\NetworkAgent');
  if not DirExists(RootDirectory) then
    Exit;
  Log('Removing existing Telesec data directory for fresh enrollment.');
  GrantPrivateDataAccess(RootDirectory);
  if not DelTree(RootDirectory, True, True, True) then
    RaiseException('Unable to remove the existing Telesec data directory.');
  Log('Existing Telesec data directory removed.');
end;

procedure PrepareAgentData;
begin
  if FreshEnrollmentRequested then
    RemoveAgentData;
  WriteBootstrap;
  ProtectAgentData;
end;

procedure ProtectAgentData;
var
  RootDirectory: String;
  PublicDirectory: String;
  ResultCode: Integer;
begin
  RootDirectory := ExpandConstant('{commonappdata}\Telesec\NetworkAgent');
  PublicDirectory := RootDirectory + '\public';
  ForceDirectories(PublicDirectory);
  GrantPrivateDataAccess(RootDirectory);
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + RootDirectory + '" /remove:g "*S-1-5-32-545" /T /C',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to restrict the Telesec agent data directory.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + RootDirectory + '" /grant:r "*S-1-5-32-545:(RX)"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to grant access to Telesec tray status.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + PublicDirectory + '" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /T /C',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to publish the Telesec tray status securely.');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
#ifdef IncludeOemDependencies
    InstallScannerDependencies;
#endif
  end;
end;
