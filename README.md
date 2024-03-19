# Trojan-Easy

Simple way to understand legitimate, clone and trojan

Version 1.0
===============================================================================

![trojangif](https://github.com/Sulaimannabdul/Trojan-Easy/assets/151133481/0ea33007-791d-4a85-ae6c-72535d7e2458) 

This paper is a Frame4 Security Systems publication, all rights reserved. You
may (re-)distribute the text as long as the content is not changed in any way
and with this header text intact. If you want to serve this paper on your web
site/FTP/Newsgroup/etc., I encourage you to do so but please do not change it
in any way without the prior permission of the author.

IMPORTANT -- THIS DOCUMENT IS FOR INFORMATIONAL PURPOSES ONLY. To the maximum
extent permitted by applicable law, in no event shall Frame4 Security Systems
be liable for any damages whatsoever, (including, without limitation, damages
for loss of any business profits, business interruption, loss of any business
information, or other pecuniary loss) arising out of the use, or inability to
use any software, and/or procedures outlined in this document, even if Frame4
Security Systems has been advised of the possibility of such damage(s). There
are NO warranties with regard to this information, but the paper may help you
improve your Windows security a lot.

This paper is the property of Frame4 Security Systems, all rights reserved.
Copyright (c) 1999-2002 Frame4 [Security Systems](http://www.frame4.com/)
-------------------------------------------------------------------------------

Author's Notes:

This is the updated version of my paper written a long while ago. During that
time I have seen it on every security/hacking site I came across and I'm glad
you're all placing it in your archives as recommended reading. Now, many more
sections and updates have been added so be sure that you will reading new and
interesting aspects regarding the topic. The paper will answer many questions
people keep asking in general about trojans like "how are attackers infecting
me" and "how to protect from trojans".

If you have any other questions about the topic including ideas, suggestions,
comments, etc., please do not hesitate to express your opinion. If you have a
lot to say on the topic and/or I have missed some aspects then please contact
me and contribute to the next update, and of course full credit will be given
to you and your ideas.
-------------------------------------------------------------------------------

Table of Contents
-----------------
01.What Is This Paper About              
02.What Is A Trojan Horse                 
03.How Do Trojans Work                           
04.Trojans Variations               
   -Remote Access Trojans <br>
   -Password Sending Trojans <br>
   -Keylogging Trojans <br>
   -Destructive Trojans <br>
   -Denial Of Service (DoS) Attack Trojans <br>
   -Proxy/Wingate Trojans <br>
   -FTP Trojans <br>
   -Detection Software Killers <br>
05.The Future Of Windows Trojans <br>
06.How Can I Get Infected <br>
   -Via ICQ <br>
   -Via IRC <br>
   -Via Attachments <br>
   -Via Physical Access <br>
   -Via Browser And E-mail Software Bugs <br>
   -Via Netbios(File Sharing) <br>
07.Fake Programs <br>
08.Untrusted Sites And FreeWare Software <br>
09.How Are They Detecting My Internet Presence <br>
10.What Is The Attacker Looking For <br>
11.Intelligence With Trojans <br>
12.Trojan Ports <br>
13.How Do I Know I'm Infected <br>
14.Anti-Virus (AV) Scanners <br>
15.Anti-Trojan Software <br>
16.After You Clean Yourself <br>
17.Online Scanning Services <br>
18.Advice <br>
19.Links Section <br>
20.Final Words <br>
-------------------------------------------------------------------------------


1.What is this paper about?
  -------------------------

The Complete Trojans Text is a paper about Windows Trojans, how they work,
their variations and, of course, strategies to minimise the risk of infection.

Links to special detection software are included as well as many other topics
never discussed before. This paper is not only intended to be for the average
Internet/Windows user who wants to know how to protect his/her machine from
Trojan Horses or just want to know about their usage, variations, prevention
and future, but will also be interesting for the advanced user, to read
another point of view.

Windows Trojans are just a small aspect of Windows Security but you will soon
realise how dangerous and destructive they could be while reading the paper.


2.What Is A Trojan Horse?
  -----------------------

A Trojan horse is:

- An unauthorised program contained within a legitimate program. This
  unauthorised program performs functions unknown (and probably unwanted) by
  the user.

- A legitimate program that has been altered by the placement of unauthorised
  code within it; this code performs functions unknown (and probably unwanted)
  by the user.

- Any program that appears to perform a desirable and necessary function but
  that (because of unauthorised code within it that is unknown to the user)
  performs functions unknown (and definitely unwanted) by the user. 

The Trojan Horse got its name from the old mythical story about how the
Greeks gave their enemy a huge wooden horse as a gift during the war. The
enemy accepted this gift and they brought it into their kingdom, and during
the night, Greek soldiers crept out of the horse and attacked the city,
completely overcoming it.


3.How Do Trojans Work?
  --------------------
  
Trojans come in two parts, a Client part and a Server part. When the victim
(unknowingly) runs the server on its machine, the attacker will then use the
Client to connect to the Server and start using the trojan. TCP/IP protocol
is the usual protocol type used for communications, but some functions of the
trojans use the UDP protocol as well. When the Server is being run on the
victim's computer, it will (usually) try to hide somewhere on the computer,
start listening on some port(s) for incoming connections from the attacker,
modify the registry and/or use some other autostarting method.

It's necessary for the attacker to know the victim's IP address to connect to
his/her machine. Many trojans have features like mailing the victim's IP, as
well as messaging the attacker via ICQ or IRC. This is used when the victim
has dynamic IP which means every time you connect to the Internet you get a
different IP (most of the dial-up users have this). ADSL users have static
IPs so the infected IP is always known to the attacker and this makes it
considerably easier to connect to your machine.

Most of the trojans use Auto-Starting methods so even when you shut down your
computer they're able to restart and again give the attacker access to your
machine. New auto-starting methods and other tricks are discovered all the
time. The variety starts from "joining" the trojan into some executable file
you use very often like explorer.exe, for example, and goes to the known
methods like modifying the system files or the Windows Registry. System files
are located in the Windows directory and here are short explanations of their
abuse by the attackers:

- Autostart Folder
  The Autostart folder is located in C:\Windows\Start Menu\Programs\startup
  and as its name suggests, automatically starts everything placed there.
- Win.ini
  Windows system file using load=Trojan.exe and run=Trojan.exe to execute
  the Trojan
- System.ini
  Using Shell=Explorer.exe trojan.exe results in execution of every file
  after Explorer.exe
- Wininit.ini
  Setup-Programs use it mostly; once run, it's being auto-deleted, which is
  very handy for trojans to restart
- Winstart.bat
  Acting as a normal bat file trojan is added as @trojan.exe to hide its
  execution from the user
- Autoexec.bat
  It's a DOS auto-starting file and it's used as auto-starting method like
  this -> c:\Trojan.exe
- Config.sys
  Could also be used as an auto-starting method for trojans
- Explorer Startup
  Is an auto-starting method for Windows95, 98, ME and if c:\explorer.exe
  exists, it will be started instead of the usual c:\Windows\Explorer.exe,
  which is the common path to the file.

Registry is often used in various auto-starting methods. Here are some known
ways:

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
"Info"="c:\directory\Trojan.exe" 
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce] 
"Info"="c:\directory\Trojan.exe"
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices]
"Info"="c:\directory\Trojan.exe"
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce]
"Info="c:\directory\Trojan.exe" 
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"Info"="c:\directory\Trojan.exe" 
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce]
"Info"="c:\directory\Trojan.exe"

- Registry Shell Open

  [HKEY_CLASSES_ROOT\exefile\shell\open\command]
  [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\open\command]

  A key with the value "%1 %*" should be placed there and if there is some
  executable file placed there, it will be executed each time you open a
  binary file. It's used like this: trojan.exe "%1 %*"; this would restart
  the trojan.

- ICQ Net Detect Method

  [HKEY_CURRENT_USER\Software\Mirabilis\ICQ\Agent\Apps\]

  This key includes all the files that will be executed if ICQ detects Internet
  connection. As you can understand,this feature of ICQ is very handy but it's
  frequently abused by attackers as well.

- ActiveX Component

  [HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components\KeyName]
  StubPath=C:\directory\Trojan.exe

These are the most common Auto-Starting methods using Windows system files, and
the Windows registry.


4.Trojans Variations
  ------------------

There are so many variations out there, it will be hard to list and describe
each and every one of them, but most are a combination of all the trojan
features you will read about below, or have many other functions still not,
and probably will never be known to the public.

Remote Access Trojans

These are probably the most publicly used trojans,just because they give the
attackers the power to do more things on the victim's machine than the victim
itself, while standing in front of the machine. Most of these trojans are
often a combination of the other variations you'll read below. The idea of
these trojans is to give the attacker a COMPLETE access to someone's machine,
and therefore access to files, private conversations, accounting data, etc.

Password Sending Trojans

The purpose of these trojans is to rip all the cached passwords and also look
for other passwords you're entering then send them to a specific mail address,
without the user noticing anything. Passwords for ICQ, IRC, FTP, HTTP or any
other application that require a user to enter a login+password are being sent
back to the attacker's e-mail address, which in most cases is located at some
free web based e-mail provider. Most of them do not restart when Windows is
loaded, as the idea is to gather as much info about the victim's machine as
passwords, mIRC logs, ICQ conversations and mail them; but it depends on the
needs of the attacker and the specific situation.

Keyloggers

These trojans are very simple.The only one thing they do is to log the
keystrokes of the victim and then let the attacker search for passwords or
other sensitive data in the log file. Most of them come with two functions
like online and offline recording. Of course they could be configured to
send the log file to a specific e-mail address on a daily basis.

Destructive

The only function of these trojans is to destroy and delete files. This makes
them very simple and easy to use. They can automatically delete all your core
system files (for example: .dll, .ini or .exe files, possibly others) on your
machine. The trojan is being activated by the attacker or sometimes works like
a logic bomb and starts on a specific day and at specific hour.

Denial Of Service (DoS) Attack Trojans

These trojans are getting very popular these days, giving the attacker power
to start DDoS if having enough victims of course. The main idea is that if you
have 200 ADSL users infected and start attacking the victim simultaneously,
this will generate a LOT of traffic (more then the victim's bandwidth, in most
cases) and its the access to the Internet will be shut down. WinTrinoo is a
DDoS tool that has become really popular recently, and if the attacker has
infected many ADSL users, major Internet sites could be shut down as a result,
as we've seen it happen in the past few months.

Another variation of a DoS trojan is the mail-bomb trojan, whose main aim is
to infect as many machines as possible and simultaneously attack specific
e-mail address/addresses with random subjects and contents which cannot be
filtered.

Proxy/Wingate Trojans

Interesting feature implemented in many trojans is turning the victim's
computer into a proxy/wingate server available to the whole world or to the
attacker only. It's used for anonymous Telnet, ICQ, IRC, etc., and also to
register domains with stolen credit cards and for many other illegal
activities. This gives the attacker complete anonymity and the chance to do
everything from YOUR computer and if he/she gets caught the trace leads back
to you.

FTP Trojans

These trojans are probably the most simple ones and are kind of outdated as
the only thing they do is to open port 21(the port for FTP transfers) and
let EVERYONE connect to your machine or just the attacker. Newer versions
are password protected so only the one that infected you may connect to your
computer.

Software Detection Killers

There are such functionalities built into some trojans, but there are also
separate programs that will kill ZoneAlarm, Norton Anti-Virus and many other
(popular anti-virus/firewall) programs, that protect your machine. When they
are disabled, the attacker will have full access to your machine, to perform
some illegal activity, use your computer to attack others and often disappear.
Even though you may notice that these programs are not working or functioning
properly, it will take you some time to remove the trojan, install the new
software, configure it and get back online with some sense of security.
