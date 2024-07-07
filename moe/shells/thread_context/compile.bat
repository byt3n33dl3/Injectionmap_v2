@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcinjector.c /link /OUT:injector.exe /SUBSYSTEM:CONSOLE /MACHINE:x64