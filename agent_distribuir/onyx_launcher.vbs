' Onyx Agent - Launcher silencioso con Auto-Update + Watchdog
' Este script:
'   1. Ejecuta onyx_updater.py (descarga ultima version si hay)
'   2. Ejecuta onyx_agent.py en modo LOOP (recolecta cada 60s)
' Si el agente ya esta corriendo, no lo lanza de nuevo.
' Completamente oculto, sin ventana de consola.

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Obtener directorio del script
strScriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)

' Buscar pythonw.exe
strPythonw = ""
arrPyVersions = Array("Python314", "Python313", "Python312", "Python311", "Python310", "Python39")

' Buscar en AppData de todos los usuarios
strUsersDir = "C:\Users"
If objFSO.FolderExists(strUsersDir) Then
    Set objUsersFolder = objFSO.GetFolder(strUsersDir)
    For Each objUserFolder In objUsersFolder.SubFolders
        For Each pyVer In arrPyVersions
            strCandidate = objUserFolder.Path & "\AppData\Local\Programs\Python\" & pyVer & "\pythonw.exe"
            If objFSO.FileExists(strCandidate) Then
                strPythonw = strCandidate
                Exit For
            End If
        Next
        If strPythonw <> "" Then Exit For
    Next
End If

' Buscar en rutas globales
If strPythonw = "" Then
    For Each pyVer In arrPyVersions
        strCandidate = "C:\Program Files\" & pyVer & "\pythonw.exe"
        If objFSO.FileExists(strCandidate) Then
            strPythonw = strCandidate
            Exit For
        End If
        strCandidate = "C:\" & pyVer & "\pythonw.exe"
        If objFSO.FileExists(strCandidate) Then
            strPythonw = strCandidate
            Exit For
        End If
    Next
End If

If strPythonw = "" Then
    ' Fallback: intentar pythonw.exe del PATH
    strPythonw = "pythonw.exe"
End If

' Verificar si el agente ya esta corriendo (evitar duplicados)
Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
Set colProcs = objWMI.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE CommandLine LIKE '%onyx_agent%' AND NOT CommandLine LIKE '%onyx_updater%' AND NOT CommandLine LIKE '%onyx_launcher%'")
bAgentRunning = False
For Each objProc In colProcs
    bAgentRunning = True
    Exit For
Next

' PASO 1: Ejecutar auto-updater (sincrono, espera que termine)
strUpdater = strScriptDir & "\onyx_updater.py"
If objFSO.FileExists(strUpdater) Then
    strCmdUpdate = """" & strPythonw & """ """ & strUpdater & """"
    objShell.Run strCmdUpdate, 0, True
End If

' PASO 2: Si el agente NO esta corriendo, lanzarlo en modo LOOP
If Not bAgentRunning Then
    strAgent = strScriptDir & "\onyx_agent.py"
    strCmdAgent = """" & strPythonw & """ """ & strAgent & """"
    objShell.Run strCmdAgent, 0, False
End If

Set objWMI = Nothing
Set objShell = Nothing
Set objFSO = Nothing
