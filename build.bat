@SETLOCAL

@SET CFLAGS=-W3 -WX -Zi -D_CRT_SECURE_NO_WARNINGS=1
@SET LFLAGS=-subsystem:console -incremental:no -opt:ref -dynamicbase user32.lib

pushd %~dp0
del /q .\build\*
mkdir .\build
pushd .\build
cl %* -Fe:"ipchanger.exe" %CFLAGS% "../ipchanger.cc" /link %LFLAGS%
cl %* -Fe:"memscan.exe" %CFLAGS% "../memscan.cc" /link %LFLAGS%
popd
popd

@ENDLOCAL
