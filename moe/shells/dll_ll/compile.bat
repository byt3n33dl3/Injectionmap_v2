@ECHO OFF

@REM Compile DLL
cl.exe /nologo /W0 /Ox /D_USRDLL /D_WINDLL injectme.c /MT /link /DLL /OUT:injectme.dll

@REM Compile Injector
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcinjector.c /link /OUT:injector.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

del *.exp
del *.lib
del *.obj