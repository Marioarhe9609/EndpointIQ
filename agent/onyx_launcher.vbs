' Onyx Agent - Launcher silencioso
' Este script ejecuta el agente Python sin mostrar ninguna ventana
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
    ' Fallback: intentar python.exe del PATH
    strPythonw = "pythonw.exe"
End If

' Ejecutar agente completamente oculto (0 = vbHide)
strAgent = strScriptDir & "\onyx_agent.py"
strCmd = """" & strPythonw & """ """ & strAgent & """ --once"
objShell.Run strCmd, 0, False

Set objShell = Nothing
Set objFSO = Nothing
