; setup.iss — Inno Setup script para IN9USBAgent
; Requer: Inno Setup 6+ (https://jrsoftware.org/isinfo.php)
;
; Para compilar:
;   iscc installer\setup.iss
; Ou via build\build_installer.bat

#define AppName      "IN9 USB Agent"
#define AppVersion   "1.3.24"
#define AppPublisher "IN9 Automacao"
#define AppExeName   "usb_agent.exe"
#define ServiceName  "IN9USBAgent"
#define InstallDir   "{autopf}\IN9Automacao\USBAgent"
#define DataDir      "{autopf}\IN9Automacao\USBAgent\data"

[Setup]
AppId={{B3A1F2C4-9D7E-4A2B-8F5C-1E6D3A9B0C2F}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=https://inventario.in9automacao.com.br
DefaultDirName={#InstallDir}
DisableDirPage=yes
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=IN9USBAgent_Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
; Ícone do instalador (opcional — remover se não existir)
; SetupIconFile=assets\icon.ico

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Files]
; Executável principal (gerado pelo PyInstaller)
Source: "..\dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{#DataDir}"; Permissions: everyone-full

[Code]
var
  ServerUrlPage: TInputQueryWizardPage;
  CollaboratorPage: TInputQueryWizardPage;

// ----------------------------------------------------------------------------
// Páginas customizadas: URL do servidor e nome do colaborador
// ----------------------------------------------------------------------------
procedure InitializeWizard;
begin
  ServerUrlPage := CreateInputQueryPage(
    wpWelcome,
    'Configuração do Servidor',
    'Informe a URL do servidor do Inventário TI.',
    ''
  );
  ServerUrlPage.Add('URL do servidor:', False);
  ServerUrlPage.Values[0] := 'https://inventario.in9automacao.com.br';

  CollaboratorPage := CreateInputQueryPage(
    ServerUrlPage.ID,
    'Dados do Colaborador',
    'Identifique o responsável por esta máquina (opcional).',
    'Este campo pode ser preenchido depois via linha de comando.'
  );
  CollaboratorPage.Add('Nome do colaborador:', False);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ServerUrlPage.ID then begin
    if Trim(ServerUrlPage.Values[0]) = '' then begin
      MsgBox('Por favor, informe a URL do servidor.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

// ----------------------------------------------------------------------------
// Após instalação dos arquivos: configurar, registrar e instalar serviço
// ----------------------------------------------------------------------------
function GetServerUrl(Param: String): String;
begin
  Result := Trim(ServerUrlPage.Values[0]);
end;

function GetCollaboratorName(Param: String): String;
begin
  Result := Trim(CollaboratorPage.Values[0]);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  Log('Parando servico existente antes de atualizar arquivos...');
  Exec('sc.exe', 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2000);
  Log('Encerrando processos antigos do agente...');
  Exec('taskkill.exe', '/F /IM {#AppExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('Removendo cadastro antigo do servico...');
  Exec('sc.exe', 'delete {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(3000);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ExePath, DataPath, ConfigParams: String;
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    ExePath  := ExpandConstant('{app}\{#AppExeName}');
    DataPath := ExpandConstant('{#DataDir}');

    // 1. Gerar token e salvar configuração (URL + nome do colaborador se informado)
    Log('Configurando agente...');
    ConfigParams := 'config --url "' + GetServerUrl('') + '"';
    if GetCollaboratorName('') <> '' then
      ConfigParams := ConfigParams + ' --user-name "' + GetCollaboratorName('') + '"';
    if not Exec(ExePath,
      ConfigParams,
      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    begin
      Log('Aviso: falha ao salvar configuração (código ' + IntToStr(ResultCode) + ')');
    end;

    // 2. Registrar no servidor (token agora válido para chamadas autenticadas)
    Log('Registrando no servidor...');
    if (not Exec(ExePath, 'register-new', ExpandConstant('{app}'),
        SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
    begin
      Log('register-new falhou (código ' + IntToStr(ResultCode) + ')');
      MsgBox('Aviso: não foi possível registrar esta máquina no servidor agora ' +
             '(rede ou servidor indisponível no momento da instalação).' + #13#10 + #13#10 +
             'Isso não impede a instalação — o agente detecta isso sozinho e tenta se ' +
             'registrar novamente em segundo plano. Se a máquina ainda não aparecer no ' +
             'portal para aprovação em alguns minutos, verifique a conectividade desta ' +
             'máquina com o servidor.', mbInformation, MB_OK);
    end
    else
      Log('register-new código: ' + IntToStr(ResultCode));

    // 3. Instalar AnyDesk + re-register com anydesk_id (cobre caso 1 e caso 2)
    Log('Instalando AnyDesk e capturando ID...');
    Exec(ExePath,
      'install-anydesk',
      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('install-anydesk código: ' + IntToStr(ResultCode));

    // 5. Instalar serviço Windows
    Log('Instalando serviço Windows...');
    if not Exec(ExePath,
      'install',
      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    begin
      MsgBox('Erro ao instalar o serviço Windows.' + #13#10 +
             'Verifique o Event Log para mais detalhes.', mbError, MB_OK);
      Exit;
    end;

    // 6. Configurar início automático com o Windows
    Log('Configurando início automático...');
    Exec('sc.exe',
      'config {#ServiceName} start= auto',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('sc config auto código: ' + IntToStr(ResultCode));

    // 7. Iniciar serviço
    Log('Iniciando serviço...');
    Exec('sc.exe',
      'start {#ServiceName}',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('sc start código: ' + IntToStr(ResultCode));
  end;
end;

// ----------------------------------------------------------------------------
// Desinstalação: parar e remover serviço, apagar dados do agente
// ----------------------------------------------------------------------------
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ExePath, DbFile: String;
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    ExePath := ExpandConstant('{app}\{#AppExeName}');

    // Parar serviço
    Exec('sc.exe', 'stop {#ServiceName}',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(2000);

    // Remover serviço
    if FileExists(ExePath) then
      Exec(ExePath, 'remove',
        ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Apagar banco de dados do agente (token, machine_id, buffer)
    // Garante que uma reinstalação gere novo token e novo registro no servidor
    DbFile := ExpandConstant('{#DataDir}\agent.db');
    if FileExists(DbFile) then
    begin
      DeleteFile(DbFile);
      Log('agent.db removido: ' + DbFile);
    end;
  end;
end;

[Registry]
; Inicia o ícone da bandeja automaticamente ao login do usuário
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
  ValueType: string; ValueName: "IN9USBAgentTray"; \
  ValueData: """{app}\{#AppExeName}"" tray"; \
  Flags: uninsdeletevalue

[Run]
; Iniciar o ícone da bandeja imediatamente após instalar (sem bloquear)
Filename: "{app}\{#AppExeName}"; Parameters: "tray"; \
  Description: "Iniciar ícone na bandeja"; \
  Flags: nowait postinstall skipifsilent runhidden

[Messages]
FinishedLabel=O {#AppName} foi instalado com sucesso e está em execução.%n%nO agente aparecerá como pendente no portal do Inventário TI e precisará ser aprovado por um administrador.
