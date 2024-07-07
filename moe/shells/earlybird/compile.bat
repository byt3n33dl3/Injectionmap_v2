@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DEBUG:FULL /Z7 /Tcinjector.c /link /OUT:injector.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
