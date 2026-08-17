' run_hidden.vbs — Truly windowless wrapper for run_local.bat
' WshShell.Run with intWindowStyle=0 (vbHide) creates ZERO console window,
' unlike PowerShell -WindowStyle Hidden which still flashes briefly.
'
' Scheduled task should call:  wscript.exe "<verify_cn>\run_hidden.vbs"
Set fso = CreateObject("Scripting.FileSystemObject")
myDir = fso.GetParentFolderName(WScript.ScriptFullName)
batPath = myDir & "\run_local.bat"
Set WshShell = CreateObject("WScript.Shell")
' 0 = hidden window, True = wait for completion (blocks until bat exits)
WshShell.Run """" & batPath & """", 0, True
