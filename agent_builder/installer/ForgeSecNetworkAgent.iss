#ifndef AgentVersion
  #define AgentVersion "0.1.0"
#endif

#define AgentName "ForgeSec Network Agent"
#define AgentExe "ForgeSecAgent.exe"
#define TrayExe "ForgeSecTray.exe"
#define ServiceName "ForgeSecNetworkAgent"

[Setup]
AppId={{19BE581B-1D21-4BEA-9CCB-DF37D02BFD72}
AppName={#AgentName}
AppVersion={#AgentVersion}
AppPublisher=ForgeSec
AppContact=ForgeSec
AppComments=Local network collector and authorized discovery service.
AppVerName={#AgentName} {#AgentVersion}
DefaultDirName={autopf}\ForgeSec\NetworkAgent
DefaultGroupName=ForgeSec
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
OutputDir=..\dist\installer
OutputBaseFilename=ForgeSec-Network-Agent-Setup-{#AgentVersion}
UninstallDisplayName={#AgentName}
UninstallDisplayIcon={app}\{#TrayExe}
SetupIconFile=assets\forgesec-agent.ico
WizardImageFile=assets\forgesec-wizard-large.bmp
WizardSmallImageFile=assets\forgesec-wizard-small.bmp
WizardImageStretch=no
VersionInfoCompany=ForgeSec
VersionInfoDescription=ForgeSec Network Agent Setup
VersionInfoProductName={#AgentName}
VersionInfoProductVersion={#AgentVersion}
SetupLogging=yes
CloseApplications=yes
RestartApplications=no

[Messages]
SetupAppTitle=ForgeSec Setup
SetupWindowTitle=ForgeSec Network Agent Setup
UninstallAppTitle=ForgeSec Uninstall
UninstallAppFullTitle=ForgeSec Network Agent Uninstall
WelcomeLabel1=Install ForgeSec Network Agent
WelcomeLabel2=This wizard enrolls a Windows collector with your ForgeSec control plane.%n%nThe agent runs as a protected service, sends outbound heartbeats, and waits for authorized discovery or scan commands.
SelectDirDesc=Choose where ForgeSec should install the agent application.
SelectDirLabel3=Setup will install ForgeSec Network Agent into this folder. Runtime identity, status, and logs are stored separately under ProgramData.
ReadyLabel1=Setup is ready to install ForgeSec Network Agent.
ReadyLabel2a=Setup will protect local agent data, register the Windows service, and start the tray status app.
InstallingLabel=Setup is installing ForgeSec Network Agent.
FinishedHeadingLabel=ForgeSec Network Agent is ready
FinishedLabel=Setup installed the Windows service and tray status app. Keep the ForgeSec dashboard open to confirm the first authenticated heartbeat.
ConfirmUninstall=This will stop ForgeSec, remove the tray app and service, delete local credentials, logs, and installed files, and clean legacy Telesec leftovers. Continue?
UninstallStatusLabel=Removing ForgeSec Network Agent...

[Files]
Source: "..\dist\agent\{#AgentExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\agent\{#TrayExe}"; DestDir: "{app}"; Flags: ignoreversion
#ifdef IncludeOemDependencies
Source: "dependencies\nmap-oem.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
#endif

[Icons]
Name: "{group}\ForgeSec Network Agent"; Filename: "{app}\{#TrayExe}"; WorkingDir: "{app}"; IconFilename: "{app}\{#TrayExe}"; Comment: "Show ForgeSec network agent status"

[Run]
#ifndef IncludeOemDependencies
Filename: "https://nmap.org/download.html"; Description: "Install Nmap and Npcap for network discovery"; Flags: shellexec nowait postinstall skipifsilent; Check: ScannerDependenciesMissing
#endif
Filename: "{app}\{#AgentExe}"; Parameters: "service install"; StatusMsg: "Preparing protected ForgeSec data and registering the service..."; Flags: runhidden waituntilterminated; BeforeInstall: PrepareAgentData
Filename: "{app}\{#AgentExe}"; Parameters: "service start"; StatusMsg: "Starting the ForgeSec Network Agent service..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#TrayExe}"; Description: "Show ForgeSec agent status in the notification area"; Flags: nowait postinstall skipifsilent

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ForgeSecNetworkAgentTray"; ValueData: """{app}\{#TrayExe}"""; Flags: uninsdeletevalue

[UninstallRun]
Filename: "{app}\{#TrayExe}"; Parameters: "--stop"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "StopForgeSecTray"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM {#TrayExe} /T /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillForgeSecTray"
Filename: "{app}\{#AgentExe}"; Parameters: "service stop"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "StopForgeSecService"
Filename: "{app}\{#AgentExe}"; Parameters: "service remove"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "RemoveForgeSecService"
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopForgeSecServiceFallback"
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteForgeSecServiceFallback"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM {#AgentExe} /T /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillForgeSecAgent"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM TelesecTray.exe /T /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillLegacyTelesecTray"
Filename: "{sys}\sc.exe"; Parameters: "stop TelesecNetworkAgent"; Flags: runhidden waituntilterminated; RunOnceId: "StopLegacyTelesecService"
Filename: "{sys}\sc.exe"; Parameters: "delete TelesecNetworkAgent"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteLegacyTelesecService"
Filename: "{sys}\taskkill.exe"; Parameters: "/IM TelesecAgent.exe /T /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillLegacyTelesecAgent"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\ForgeSec\NetworkAgent"
Type: dirifempty; Name: "{commonappdata}\ForgeSec"
Type: filesandordirs; Name: "{app}"
Type: dirifempty; Name: "{autopf}\ForgeSec"
Type: filesandordirs; Name: "{commonappdata}\Telesec\NetworkAgent"
Type: dirifempty; Name: "{commonappdata}\Telesec"
Type: filesandordirs; Name: "{autopf}\Telesec\NetworkAgent"
Type: dirifempty; Name: "{autopf}\Telesec"

[Code]
var
  EnrollmentPage: TInputQueryWizardPage;

procedure ApplyForgeSecWizardStyle;
begin
  WizardForm.Caption := 'ForgeSec Network Agent Setup';
  WizardForm.WelcomeLabel1.Caption := 'Install ForgeSec Network Agent';
  WizardForm.WelcomeLabel2.Caption :=
    'This wizard enrolls a Windows collector with your ForgeSec control plane.' + #13#10#13#10 +
    'The agent runs as a protected service, sends outbound heartbeats, and waits for authorized discovery or scan commands.';
  WizardForm.FinishedHeadingLabel.Caption := 'ForgeSec Network Agent is ready';
  WizardForm.FinishedLabel.Caption :=
    'Setup installed the Windows service and tray status app. Keep the ForgeSec dashboard open to confirm the first authenticated heartbeat.';
  WizardForm.WelcomeLabel1.Font.Name := 'Segoe UI';
  WizardForm.WelcomeLabel1.Font.Style := [fsBold];
  WizardForm.WelcomeLabel2.Font.Name := 'Segoe UI';
  WizardForm.PageNameLabel.Font.Name := 'Segoe UI';
  WizardForm.PageNameLabel.Font.Style := [fsBold];
  WizardForm.PageDescriptionLabel.Font.Name := 'Segoe UI';
  WizardForm.FinishedHeadingLabel.Font.Name := 'Segoe UI';
  WizardForm.FinishedHeadingLabel.Font.Style := [fsBold];
  WizardForm.FinishedLabel.Font.Name := 'Segoe UI';
end;

procedure SetWizardPageText(PageName: String; PageDescription: String);
begin
  WizardForm.PageNameLabel.Caption := PageName;
  WizardForm.PageDescriptionLabel.Caption := PageDescription;
end;

function FreshEnrollmentRequested: Boolean;
var
  Value: String;
begin
  Value := Lowercase(Trim(ExpandConstant('{param:RESETAGENTDATA|0}')));
  Result := (Value = '1') or (Value = 'true') or (Value = 'yes');
end;

function ExistingEnrollment: Boolean;
begin
  Result := (not FreshEnrollmentRequested) and FileExists(ExpandConstant('{commonappdata}\ForgeSec\NetworkAgent\identity\identity.json'));
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
  StringChangeEx(Result, #9, '\t', True);
end;

procedure InitializeWizard;
begin
  ApplyForgeSecWizardStyle;
  EnrollmentPage := CreateInputQueryPage(
    wpSelectDir,
    'Enroll this collector',
    'Paste the ForgeSec control server details.',
    'Create a one-time token in the ForgeSec dashboard before continuing. HTTPS is required except for a server running on this computer.'
  );
  EnrollmentPage.Add('ForgeSec server URL:', False);
  EnrollmentPage.Add('One-time enrollment token:', True);
  EnrollmentPage.Values[0] := ExpandConstant('{param:SERVERURL|http://127.0.0.1:8000}');
  EnrollmentPage.Values[1] := ExpandConstant('{param:ENROLLMENTTOKEN|}');
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpSelectDir then
    SetWizardPageText(
      'Choose install location',
      'The application files install here. Runtime identity and logs stay protected under ProgramData.'
    );
  if CurPageID = EnrollmentPage.ID then
    SetWizardPageText(
      'Enroll this collector',
      'Paste the ForgeSec server URL and one-time token from the dashboard.'
    );
  if CurPageID = wpReady then
    SetWizardPageText(
      'Ready to install',
      'ForgeSec will prepare protected local data, register the Windows service, and start the tray status app.'
    );
  if CurPageID = wpInstalling then
    SetWizardPageText(
      'Installing ForgeSec',
      'Please wait while Setup configures the local network collector.'
    );
end;

procedure InitializeUninstallProgressForm;
begin
  UninstallProgressForm.Caption := 'ForgeSec Network Agent Uninstall';
  UninstallProgressForm.StatusLabel.Caption := 'Preparing ForgeSec cleanup...';
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
    Result := 'Enter an HTTPS ForgeSec server URL. HTTP is allowed only for localhost.';
    Exit;
  end;
  if Length(Trim(EnrollmentPage.Values[1])) < 32 then
    Result := 'Enter a valid one-time enrollment token from the ForgeSec dashboard.';
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
procedure PrepareUninstallCleanup; forward;
procedure FinishUninstallCleanup; forward;
#ifdef IncludeOemDependencies
procedure InstallScannerDependencies; forward;
#endif

procedure ExecQuiet(FileName: String; Parameters: String);
var
  ResultCode: Integer;
begin
  Exec(
    FileName,
    Parameters,
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
end;

procedure StopProcess(ImageName: String);
begin
  ExecQuiet(ExpandConstant('{sys}\taskkill.exe'), '/IM ' + ImageName + ' /T /F');
end;

procedure RemoveServiceByName(ServiceToRemove: String);
begin
  ExecQuiet(ExpandConstant('{sys}\sc.exe'), 'stop ' + ServiceToRemove);
  ExecQuiet(ExpandConstant('{sys}\sc.exe'), 'delete ' + ServiceToRemove);
end;

procedure TryGrantDeleteAccess(RootDirectory: String);
begin
  if not DirExists(RootDirectory) then
    Exit;
  ExecQuiet(ExpandConstant('{sys}\takeown.exe'), '/F "' + RootDirectory + '" /A /R /D Y');
  ExecQuiet(ExpandConstant('{sys}\icacls.exe'), '"' + RootDirectory + '" /inheritance:e /T /C');
  ExecQuiet(ExpandConstant('{sys}\icacls.exe'), '"' + RootDirectory + '" /grant "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C');
end;

procedure DeleteResidualDirectory(DirectoryPath: String);
begin
  if not DirExists(DirectoryPath) then
    Exit;
  TryGrantDeleteAccess(DirectoryPath);
  if not DelTree(DirectoryPath, True, True, True) then
    Log('Unable to delete residual directory: ' + DirectoryPath);
end;

procedure StopInstalledTray;
var
  ExistingTray: String;
begin
  ExistingTray := ExpandConstant('{app}\{#TrayExe}');
  if FileExists(ExistingTray) then
    ExecQuiet(ExistingTray, '--stop');
  StopProcess('{#TrayExe}');
  StopProcess('TelesecTray.exe');
end;

procedure RemoveInstalledServices;
var
  ExistingAgent: String;
begin
  ExistingAgent := ExpandConstant('{app}\{#AgentExe}');
  if FileExists(ExistingAgent) then
  begin
    ExecQuiet(ExistingAgent, 'service stop');
    ExecQuiet(ExistingAgent, 'service remove');
  end;
  RemoveServiceByName('{#ServiceName}');
  RemoveServiceByName('TelesecNetworkAgent');
  StopProcess('{#AgentExe}');
  StopProcess('TelesecAgent.exe');
end;

procedure RemoveStartupEntries;
begin
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ForgeSecNetworkAgentTray');
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'TelesecNetworkAgentTray');
end;

procedure PrepareUninstallCleanup;
begin
  UninstallProgressForm.StatusLabel.Caption := 'Stopping ForgeSec tray and service...';
  StopInstalledTray;
  RemoveInstalledServices;
  RemoveStartupEntries;
  TryGrantDeleteAccess(ExpandConstant('{commonappdata}\ForgeSec\NetworkAgent'));
  TryGrantDeleteAccess(ExpandConstant('{commonappdata}\Telesec\NetworkAgent'));
end;

procedure FinishUninstallCleanup;
begin
  UninstallProgressForm.StatusLabel.Caption := 'Removing ForgeSec files and protected data...';
  StopInstalledTray;
  RemoveInstalledServices;
  RemoveStartupEntries;
  DeleteResidualDirectory(ExpandConstant('{commonappdata}\ForgeSec\NetworkAgent'));
  DeleteResidualDirectory(ExpandConstant('{app}'));
  DeleteResidualDirectory(ExpandConstant('{commonappdata}\Telesec\NetworkAgent'));
  DeleteResidualDirectory(ExpandConstant('{autopf}\Telesec\NetworkAgent'));
end;

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
      'Nmap or Npcap is missing. ForgeSec Setup will now install both scanner dependencies automatically.',
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
    RaiseException('Unable to take ownership of the ForgeSec data directory.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + RootDirectory + '" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to grant direct access to the ForgeSec data directory.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + RootDirectory + '" /grant "*S-1-5-18:F" "*S-1-5-32-544:F" /T /C',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to grant file access to the ForgeSec data directory.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + RootDirectory + '" /grant "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to grant inherited access to the ForgeSec data directory.');
end;

procedure WriteBootstrap;
var
  ConfigDirectory: String;
  ConfigPath: String;
  RootDirectory: String;
  BootstrapJson: String;
begin
  if ExistingEnrollment then
  begin
    Log('ForgeSec bootstrap unchanged because an existing enrollment is present.');
    Exit;
  end;
  RootDirectory := ExpandConstant('{commonappdata}\ForgeSec\NetworkAgent');
  ConfigDirectory := ExpandConstant('{commonappdata}\ForgeSec\NetworkAgent\config');
  ConfigPath := ConfigDirectory + '\bootstrap.json';
  WizardForm.StatusLabel.Caption := 'Writing secure ForgeSec enrollment data...';
  Log('Writing ForgeSec bootstrap configuration to ' + ConfigPath);
  ForceDirectories(ConfigDirectory);
  GrantPrivateDataAccess(RootDirectory);
  if FileExists(ConfigPath) and (not DeleteFile(ConfigPath)) then
    RaiseException('Unable to replace the ForgeSec bootstrap configuration.');
  BootstrapJson :=
    '{"server_url":"' + JsonEscape(Trim(EnrollmentPage.Values[0])) +
    '","enrollment_token":"' + JsonEscape(Trim(EnrollmentPage.Values[1])) + '"}' + #10;
  if not SaveStringToFile(ConfigPath, UTF8Encode(BootstrapJson), False) then
    RaiseException('Unable to write the ForgeSec bootstrap configuration.');
  Log('ForgeSec bootstrap configuration written.');
end;

procedure RemoveAgentData;
var
  RootDirectory: String;
begin
  RootDirectory := ExpandConstant('{commonappdata}\ForgeSec\NetworkAgent');
  if not DirExists(RootDirectory) then
    Exit;
  Log('Removing existing ForgeSec data directory for fresh enrollment.');
  GrantPrivateDataAccess(RootDirectory);
  if not DelTree(RootDirectory, True, True, True) then
    RaiseException('Unable to remove the existing ForgeSec data directory.');
  Log('Existing ForgeSec data directory removed.');
end;

procedure PrepareAgentData;
begin
#ifdef IncludeOemDependencies
  InstallScannerDependencies;
#endif
  WizardForm.StatusLabel.Caption := 'Preparing protected ForgeSec data...';
  if FreshEnrollmentRequested then
    RemoveAgentData;
  WriteBootstrap;
  WizardForm.StatusLabel.Caption := 'Applying ForgeSec data permissions...';
  ProtectAgentData;
end;

procedure ProtectAgentData;
var
  RootDirectory: String;
  PublicDirectory: String;
  LogDirectory: String;
  ResultCode: Integer;
begin
  RootDirectory := ExpandConstant('{commonappdata}\ForgeSec\NetworkAgent');
  PublicDirectory := RootDirectory + '\public';
  LogDirectory := RootDirectory + '\logs';
  ForceDirectories(PublicDirectory);
  ForceDirectories(LogDirectory);
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
    RaiseException('Unable to restrict the ForgeSec agent data directory.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + RootDirectory + '" /grant:r "*S-1-5-32-545:(RX)"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to grant access to ForgeSec tray status.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + PublicDirectory + '" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /T /C',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to publish the ForgeSec tray status securely.');
  Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + LogDirectory + '" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /T /C',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
  if ResultCode <> 0 then
    RaiseException('Unable to publish the ForgeSec agent logs securely.');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    PrepareUninstallCleanup;
  if CurUninstallStep = usPostUninstall then
    FinishUninstallCleanup;
end;
