Unicode true
RequestExecutionLevel admin

!include "MUI2.nsh"
!include "LogicLib.nsh"

Name "Excalibur"
OutFile "..\dist\ExcaliburSetup.exe"
InstallDir "$PROGRAMFILES64\Excalibur"
InstallDirRegKey HKLM "Software\Excalibur" "InstallDir"

!define APP_NAME "Excalibur"
!define APP_VERSION "0.1.0"
!define PYTHON_INSTALLER "python-3.13.14-amd64.exe"
!define NPCAP_INSTALLER "npcap-1.88.exe"

Var PayloadDir
Var PythonDir

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Function .onInit
    SetRegView 64
    UserInfo::GetAccountType
    Pop $0

    ${If} $0 != "admin"
        MessageBox MB_ICONSTOP "Administrator privileges are required to install Excalibur."
        Abort
    ${EndIf}
FunctionEnd

Function EnsurePython
    DetailPrint "Checking Python..."

    ExecWait 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "python --version | Out-Null"' $0

    ${If} $0 == 0
        DetailPrint "Python detected."
        Return
    ${EndIf}

    DetailPrint "Python not found. Installing bundled Python 3.13.14..."

    ExecWait '"$PayloadDir\third_party\python\${PYTHON_INSTALLER}" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0' $0

    ${If} $0 != 0
        MessageBox MB_ICONSTOP "Python installation failed with exit code $0."
        Abort
    ${EndIf}

    StrCpy $PythonDir "$PROGRAMFILES64\Python313"

    ${IfNot} ${FileExists} "$PythonDir\python.exe"
        MessageBox MB_ICONSTOP "Python installer finished, but $PythonDir\python.exe was not found."
        Abort
    ${EndIf}

    DetailPrint "Python installed successfully."
FunctionEnd

Function EnsureNpcap
    DetailPrint "Checking Npcap..."

    ExecWait 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (Get-Service npcap -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"' $0

    ${If} $0 == 0
        DetailPrint "Npcap detected."
        Return
    ${EndIf}

    MessageBox MB_ICONINFORMATION "Npcap is required for packet capture. The bundled Npcap installer will now open. Complete the Npcap setup, then Excalibur installation will continue."

    ExecWait '"$PayloadDir\third_party\npcap\${NPCAP_INSTALLER}"' $0

    ExecWait 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (Get-Service npcap -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"' $0

    ${If} $0 != 0
        MessageBox MB_ICONEXCLAMATION "Npcap was not detected after installation. Excalibur may install, but packet capture may not work until Npcap is installed."
    ${EndIf}
FunctionEnd

Function RunExcaliburInstall
    DetailPrint "Running Excalibur PowerShell installer..."

    FileOpen $9 "$PLUGINSDIR\run-excalibur-install.ps1" w
    FileWrite $9 '$$ErrorActionPreference = "Stop"$\r$\n'
    FileWrite $9 '$$pythonDir = "$PROGRAMFILES64\Python313"$\r$\n'
    FileWrite $9 '$$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")$\r$\n'
    FileWrite $9 '$$userPath = [Environment]::GetEnvironmentVariable("Path", "User")$\r$\n'
    FileWrite $9 '$$env:Path = "$PROGRAMFILES64\Python313;$PROGRAMFILES64\Python313\Scripts;" + $$machinePath + ";" + $$userPath$\r$\n'
    FileWrite $9 '& "$PayloadDir\scripts\windows\install.ps1" -AppDir "$INSTDIR" -DataDir "$COMMONAPPDATA\Excalibur"$\r$\n'
    FileClose $9

    ExecWait 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\run-excalibur-install.ps1"' $0

    ${If} $0 != 0
        MessageBox MB_ICONSTOP "Excalibur installation failed with exit code $0."
        Abort
    ${EndIf}
FunctionEnd

Section "Install Excalibur" SecInstall
    SetRegView 64
    SetShellVarContext all

    InitPluginsDir
    StrCpy $PayloadDir "$PLUGINSDIR\payload"

    DetailPrint "Extracting Excalibur payload..."
    SetOutPath "$PayloadDir"

    File /r \
        /x ".git" \
        /x ".venv" \
        /x "__pycache__" \
        /x "*.pyc" \
        /x "*.sqlite*" \
        /x "dist" \
        "..\*.*"

    ${IfNot} ${FileExists} "$PayloadDir\scripts\windows\install.ps1"
        MessageBox MB_ICONSTOP "Installer payload is incomplete: scripts\windows\install.ps1 was not found."
        Abort
    ${EndIf}

    ${IfNot} ${FileExists} "$PayloadDir\third_party\python\${PYTHON_INSTALLER}"
        MessageBox MB_ICONSTOP "Installer payload is incomplete: bundled Python installer was not found."
        Abort
    ${EndIf}

    ${IfNot} ${FileExists} "$PayloadDir\third_party\npcap\${NPCAP_INSTALLER}"
        MessageBox MB_ICONSTOP "Installer payload is incomplete: bundled Npcap installer was not found."
        Abort
    ${EndIf}

    ${IfNot} ${FileExists} "$PayloadDir\third_party\winsw\WinSW-x64.exe"
        MessageBox MB_ICONSTOP "Installer payload is incomplete: bundled WinSW executable was not found."
        Abort
    ${EndIf}

    Call EnsurePython
    Call EnsureNpcap
    Call RunExcaliburInstall

    DetailPrint "Creating shortcuts..."

    CreateDirectory "$SMPROGRAMS\Excalibur"

    WriteINIStr "$SMPROGRAMS\Excalibur\Excalibur Dashboard.url" "InternetShortcut" "URL" "http://127.0.0.1:5000"

    WriteUninstaller "$INSTDIR\Uninstall.exe"

    CreateShortcut "$SMPROGRAMS\Excalibur\Uninstall Excalibur.lnk" "$INSTDIR\Uninstall.exe"

    WriteRegStr HKLM "Software\Excalibur" "InstallDir" "$INSTDIR"

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Excalibur" "DisplayName" "Excalibur"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Excalibur" "DisplayVersion" "${APP_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Excalibur" "Publisher" "Excalibur"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Excalibur" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Excalibur" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Excalibur" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Excalibur" "NoRepair" 1

    MessageBox MB_ICONINFORMATION "Excalibur installation completed.$\r$\n$\r$\nDashboard: http://127.0.0.1:5000"
SectionEnd

Section "Uninstall"
    SetRegView 64
    SetShellVarContext all

    ${If} ${FileExists} "$INSTDIR\scripts\windows\uninstall.ps1"
        ExecWait 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\scripts\windows\uninstall.ps1"' $0
    ${Else}
        MessageBox MB_ICONEXCLAMATION "Excalibur uninstall script was not found. Removing installer registration only."
    ${EndIf}

    Delete "$SMPROGRAMS\Excalibur\Excalibur Dashboard.url"
    Delete "$SMPROGRAMS\Excalibur\Uninstall Excalibur.lnk"
    RMDir "$SMPROGRAMS\Excalibur"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Excalibur"
    DeleteRegKey HKLM "Software\Excalibur"
SectionEnd