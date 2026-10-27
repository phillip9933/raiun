; Safe in-place upgrade guard for Raiun Desktop.
; Tauri's standard install-time CheckIfAppIsRunning uses Restart Manager's
; RmForceShutdown. We instead refuse to replace executable files while either
; product process still has them open. The user can quit normally and retry.

!macro RaiunCheckInstallProcesses
raiun_check_install_processes:
  StrCpy $R1 0
  ${If} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
    StrCpy $R1 1
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\raiun-agent.exe"
    StrCpy $R1 1
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\raiun.exe"
    StrCpy $R1 1
  ${EndIf}
  ${If} $R1 = 0
    Goto raiun_check_install_done
  ${EndIf}

  !insertmacro RestartManager_StartSession $R0
  ${If} $R0 == ""
    Abort "Raiun could not check whether its files are in use. Close Raiun and retry."
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
    !insertmacro RestartManager_RegisterFile $R0 "$INSTDIR\${MAINBINARYNAME}.exe"
    ${If} $0 != 0
      !insertmacro RestartManager_EndSession $R0
      Abort "Raiun could not check whether its files are in use. Close Raiun and retry."
    ${EndIf}
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\raiun-agent.exe"
    !insertmacro RestartManager_RegisterFile $R0 "$INSTDIR\raiun-agent.exe"
    ${If} $0 != 0
      !insertmacro RestartManager_EndSession $R0
      Abort "Raiun could not check whether its files are in use. Close Raiun and retry."
    ${EndIf}
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\raiun.exe"
    !insertmacro RestartManager_RegisterFile $R0 "$INSTDIR\raiun.exe"
    ${If} $0 != 0
      !insertmacro RestartManager_EndSession $R0
      Abort "Raiun could not check whether its files are in use. Close Raiun and retry."
    ${EndIf}
  ${EndIf}

  ; pnProcInfo is in/out and must start at zero for a sizing-only first call.
  ; ERROR_MORE_DATA (234) means at least one registered process still uses a file.
  System::Call 'RSTRTMGR::RmGetList(i R0, *i .r1, *i 0r2, p 0, *i .r3) i .r4'
  !insertmacro RestartManager_EndSession $R0
  ${If} $4 = 0
    Goto raiun_check_install_done
  ${ElseIf} $4 = 234
    IfSilent raiun_check_install_silent_busy
    MessageBox MB_ICONEXCLAMATION|MB_RETRYCANCEL "Quit Raiun Desktop, its background agent, and any Raiun CLI process normally, then choose Retry. No process will be stopped automatically." IDRETRY raiun_check_install_processes IDCANCEL raiun_check_install_cancelled
  ${Else}
    Abort "Raiun could not verify that its files are closed. No files were replaced."
  ${EndIf}

raiun_check_install_silent_busy:
  Abort "A Raiun Desktop, agent, or CLI process is still running. Quit it normally and retry the installer."

raiun_check_install_cancelled:
  Abort "The upgrade was cancelled. No application files were replaced."

raiun_check_install_done:
!macroend
