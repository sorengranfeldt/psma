@echo off
echo Building PSMA x64 with MSBuild 2022...
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" "Granfeldt.PowerShell.ManagementAgent.sln" /p:Configuration=Release /p:Platform=x64 /v:normal
echo Build completed with exit code %ERRORLEVEL%
