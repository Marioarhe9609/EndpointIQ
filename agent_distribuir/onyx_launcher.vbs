' Onyx Agent - Launcher silencioso v3.1
' 1. Lee la ruta exacta de Python guardada por el instalador
' 2. Ejecuta el updater (descarga nueva version si hay)
' 3. Lanza el agente en modo loop si no esta corriendo

Set objShell = CreateObject("WScript.Shell")
Set objFSO   = CreateObject("Scripting.FileSystemObject")

strScriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)

' ── Obtener ruta de Python ──────────────────────────────────────
strPythonw = ""

' Primero: leer python_path.txt guardado por el instalador
strPythonPathFile = strScriptDir & "\python_path.txt"
If objFSO.FileExists(strPythonPathFile) Then
    Set f = objFSO.OpenTextFile(strPythonPathFile, 1)
    strPythonPath = Trim(f.ReadAll())
    f.Close
    ' Convertir python.exe -> pythonw.exe para ejecucion silenciosa
    strPythonw = Replace(strPythonPath, "\python.exe", "\pythonw.exe")
    If Not objFSO.FileExists(strPythonw) Then
        strPythonw = strPythonPath  ' Si no hay pythonw, usar python.exe igual
    End If
End If

' Segundo: buscar en AppData de todos los usuarios
If strPythonw = "" Then
    arrPyVersions = Array("Python314","Python313","Python312","Python311","Python310","Python39")
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
End If

' Tercero: buscar en rutas globales
If strPythonw = "" Then
    arrPyVersions = Array("Python314","Python313","Python312","Python311","Python310","Python39")
    For Each pyVer In arrPyVersions
        For Each strBase In Array("C:\Program Files", "C:")
            strCandidate = strBase & "\" & pyVer & "\pythonw.exe"
            If objFSO.FileExists(strCandidate) Then
                strPythonw = strCandidate
                Exit For
            End If
        Next
        If strPythonw <> "" Then Exit For
    Next
End If

' Fallback final
If strPythonw = "" Then strPythonw = "pythonw.exe"

' ── Verificar si el agente ya corre (evitar duplicados) ─────────
Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
Set colProcs = objWMI.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE CommandLine LIKE '%onyx_agent%' AND NOT CommandLine LIKE '%onyx_updater%' AND NOT CommandLine LIKE '%onyx_launcher%'")
bAgentRunning = False
For Each objProc In colProcs
    bAgentRunning = True
    Exit For
Next

' ── Paso 1: Auto-updater (sincrono) ─────────────────────────────
strUpdater = strScriptDir & "\onyx_updater.py"
If objFSO.FileExists(strUpdater) Then
    strCmdUpdate = """" & strPythonw & """ """ & strUpdater & """"
    objShell.Run strCmdUpdate, 0, True
End If

' ── Paso 2: Lanzar agente si no corre ───────────────────────────
If Not bAgentRunning Then
    strAgent = strScriptDir & "\onyx_agent.py"
    strCmdAgent = """" & strPythonw & """ """ & strAgent & """"
    objShell.Run strCmdAgent, 0, False
End If

Set objWMI    = Nothing
Set objShell  = Nothing
Set objFSO    = Nothing
