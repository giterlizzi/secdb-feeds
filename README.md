# SecDB - Security Feeds
Security feeds for SecDB (https://secdb.nttzen.cloud)

## Log4Shell

### References
- https://en.wikipedia.org/wiki/Log4Shell (Log4Shell, Wikipedia)
- https://log4shell.com (Log4Shell, Official Website)


### [CVE-2021-44228](https://secdb.nttzen.cloud/cve/detail/CVE-2021-44228)

Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

[![CVE-2021-44228](https://secdb.nttzen.cloud/cve/badge/CVE-2021-44228)](https://secdb.nttzen.cloud/cve/detail/CVE-2021-44228)



## ShellShock

### [CVE-2014-6271](https://secdb.nttzen.cloud/cve/detail/CVE-2014-6271)

GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

[![CVE-2014-6271](https://secdb.nttzen.cloud/cve/badge/CVE-2014-6271)](https://secdb.nttzen.cloud/cve/detail/CVE-2014-6271)

### [CVE-2014-6277](https://secdb.nttzen.cloud/cve/detail/CVE-2014-6277)

GNU Bash through 4.3 bash43-026 does not properly parse function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code or cause a denial of service (uninitialized memory access, and untrusted-pointer read and write operations) via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271 and CVE-2014-7169.

[![CVE-2014-6277](https://secdb.nttzen.cloud/cve/badge/CVE-2014-6277)](https://secdb.nttzen.cloud/cve/detail/CVE-2014-6277)

### [CVE-2014-6278](https://secdb.nttzen.cloud/cve/detail/CVE-2014-6278)

GNU Bash through 4.3 bash43-026 does not properly parse function definitions in the values of environment variables, which allows remote attackers to execute arbitrary commands via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271, CVE-2014-7169, and CVE-2014-6277.

[![CVE-2014-6278](https://secdb.nttzen.cloud/cve/badge/CVE-2014-6278)](https://secdb.nttzen.cloud/cve/detail/CVE-2014-6278)

### [CVE-2014-7169](https://secdb.nttzen.cloud/cve/detail/CVE-2014-7169)

GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in the values of environment variables, which allows remote attackers to write to files or possibly have unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271.

[![CVE-2014-7169](https://secdb.nttzen.cloud/cve/badge/CVE-2014-7169)](https://secdb.nttzen.cloud/cve/detail/CVE-2014-7169)

### [CVE-2014-7186](https://secdb.nttzen.cloud/cve/detail/CVE-2014-7186)

The redirection implementation in parse.y in GNU Bash through 4.3 bash43-026 allows remote attackers to cause a denial of service (out-of-bounds array access and application crash) or possibly have unspecified other impact via crafted use of here documents, aka the "redir_stack" issue.

[![CVE-2014-7186](https://secdb.nttzen.cloud/cve/badge/CVE-2014-7186)](https://secdb.nttzen.cloud/cve/detail/CVE-2014-7186)

### [CVE-2014-7187](https://secdb.nttzen.cloud/cve/detail/CVE-2014-7187)

Off-by-one error in the read_token_word function in parse.y in GNU Bash through 4.3 bash43-026 allows remote attackers to cause a denial of service (out-of-bounds array access and application crash) or possibly have unspecified other impact via deeply nested for loops, aka the "word_lineno" issue.

[![CVE-2014-7187](https://secdb.nttzen.cloud/cve/badge/CVE-2014-7187)](https://secdb.nttzen.cloud/cve/detail/CVE-2014-7187)



## Heartbleed

### [CVE-2014-0160](https://secdb.nttzen.cloud/cve/detail/CVE-2014-0160)

The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

[![CVE-2014-0160](https://secdb.nttzen.cloud/cve/badge/CVE-2014-0160)](https://secdb.nttzen.cloud/cve/detail/CVE-2014-0160)



## BlueKeep

### [CVE-2019-0708](https://secdb.nttzen.cloud/cve/detail/CVE-2019-0708)

A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'.

[![CVE-2019-0708](https://secdb.nttzen.cloud/cve/badge/CVE-2019-0708)](https://secdb.nttzen.cloud/cve/detail/CVE-2019-0708)



## Meltdown

### [CVE-2017-5754](https://secdb.nttzen.cloud/cve/detail/CVE-2017-5754)

Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.

[![CVE-2017-5754](https://secdb.nttzen.cloud/cve/badge/CVE-2017-5754)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-5754)



## Spectre

### [CVE-2017-5753](https://secdb.nttzen.cloud/cve/detail/CVE-2017-5753)

Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

[![CVE-2017-5753](https://secdb.nttzen.cloud/cve/badge/CVE-2017-5753)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-5753)

### [CVE-2017-5715](https://secdb.nttzen.cloud/cve/detail/CVE-2017-5715)

Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

[![CVE-2017-5715](https://secdb.nttzen.cloud/cve/badge/CVE-2017-5715)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-5715)



## EternalBlue

### [CVE-2017-0144](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0144)

The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

[![CVE-2017-0144](https://secdb.nttzen.cloud/cve/badge/CVE-2017-0144)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0144)



## POODLE

### [CVE-2014-3566](https://secdb.nttzen.cloud/cve/detail/CVE-2014-3566)

The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other products, uses nondeterministic CBC padding, which makes it easier for man-in-the-middle attackers to obtain cleartext data via a padding-oracle attack, aka the "POODLE" issue.

[![CVE-2014-3566](https://secdb.nttzen.cloud/cve/badge/CVE-2014-3566)](https://secdb.nttzen.cloud/cve/detail/CVE-2014-3566)



## SMBGhost

### [CVE-2020-0796](https://secdb.nttzen.cloud/cve/detail/CVE-2020-0796)

A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

[![CVE-2020-0796](https://secdb.nttzen.cloud/cve/badge/CVE-2020-0796)](https://secdb.nttzen.cloud/cve/detail/CVE-2020-0796)



## PrintNightmare

### [CVE-2021-1675](https://secdb.nttzen.cloud/cve/detail/CVE-2021-1675)

Windows Print Spooler Remote Code Execution Vulnerability

[![CVE-2021-1675](https://secdb.nttzen.cloud/cve/badge/CVE-2021-1675)](https://secdb.nttzen.cloud/cve/detail/CVE-2021-1675)

### [CVE-2021-34527](https://secdb.nttzen.cloud/cve/detail/CVE-2021-34527)

<p>A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.</p>
<p>UPDATE July 7, 2021: The security update for Windows Server 2012, Windows Server 2016 and Windows 10, Version 1607 have been released. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability.</p>
<p>In addition to installing the updates, in order to secure your system, you must confirm that the following registry settings are set to 0 (zero) or are not defined (<strong>Note</strong>: These registry keys do not exist by default, and therefore are already at the secure setting.), also that your Group Policy setting are correct (see FAQ):</p>
<ul>
<li>HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint</li>
<li>NoWarningNoElevationOnInstall = 0 (DWORD) or not defined (default setting)</li>
<li>UpdatePromptSettings = 0 (DWORD) or not defined (default setting)</li>
</ul>
<p><strong>Having NoWarningNoElevationOnInstall set to 1 makes your system vulnerable by design.</strong></p>
<p>UPDATE July 6, 2021: Microsoft has completed the investigation and has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability. See also <a href="https://support.microsoft.com/topic/31b91c02-05bc-4ada-a7ea-183b129578a7">KB5005010: Restricting installation of new printer drivers after applying the July 6, 2021 updates</a>.</p>
<p>Note that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527.</p>

[![CVE-2021-34527](https://secdb.nttzen.cloud/cve/badge/CVE-2021-34527)](https://secdb.nttzen.cloud/cve/detail/CVE-2021-34527)



## KRACK

### References
- https://en.wikipedia.org/wiki/KRACK (KRACK, Wikipedia)


### [CVE-2017-13077](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13077)

Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Pairwise Transient Key (PTK) Temporal Key (TK) during the four-way handshake, allowing an attacker within radio range to replay, decrypt, or spoof frames.

[![CVE-2017-13077](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13077)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13077)

### [CVE-2017-13078](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13078)

Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Group Temporal Key (GTK) during the four-way handshake, allowing an attacker within radio range to replay frames from access points to clients.

[![CVE-2017-13078](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13078)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13078)

### [CVE-2017-13079](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13079)

Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity Group Temporal Key (IGTK) during the four-way handshake, allowing an attacker within radio range to spoof frames from access points to clients.

[![CVE-2017-13079](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13079)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13079)

### [CVE-2017-13080](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13080)

Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Group Temporal Key (GTK) during the group key handshake, allowing an attacker within radio range to replay frames from access points to clients.

[![CVE-2017-13080](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13080)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13080)

### [CVE-2017-13081](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13081)

Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity Group Temporal Key (IGTK) during the group key handshake, allowing an attacker within radio range to spoof frames from access points to clients.

[![CVE-2017-13081](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13081)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13081)

### [CVE-2017-13082](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13082)

Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11r allows reinstallation of the Pairwise Transient Key (PTK) Temporal Key (TK) during the fast BSS transmission (FT) handshake, allowing an attacker within radio range to replay, decrypt, or spoof frames.

[![CVE-2017-13082](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13082)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13082)

### [CVE-2017-13084](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13084)

Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Station-To-Station-Link (STSL) Transient Key (STK) during the PeerKey handshake, allowing an attacker within radio range to replay, decrypt, or spoof frames.

[![CVE-2017-13084](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13084)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13084)

### [CVE-2017-13086](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13086)

Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Tunneled Direct-Link Setup (TDLS) Peer Key (TPK) during the TDLS handshake, allowing an attacker within radio range to replay, decrypt, or spoof frames.

[![CVE-2017-13086](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13086)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13086)

### [CVE-2017-13087](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13087)

Wi-Fi Protected Access (WPA and WPA2) that support 802.11v allows reinstallation of the Group Temporal Key (GTK) when processing a Wireless Network Management (WNM) Sleep Mode Response frame, allowing an attacker within radio range to replay frames from access points to clients.

[![CVE-2017-13087](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13087)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13087)

### [CVE-2017-13088](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13088)

Wi-Fi Protected Access (WPA and WPA2) that support 802.11v allows reinstallation of the Integrity Group Temporal Key (IGTK) when processing a Wireless Network Management (WNM) Sleep Mode Response frame, allowing an attacker within radio range to replay frames from access points to clients.

[![CVE-2017-13088](https://secdb.nttzen.cloud/cve/badge/CVE-2017-13088)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13088)



## PwnKit

### [CVE-2021-4034](https://secdb.nttzen.cloud/cve/detail/CVE-2021-4034)

A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

[![CVE-2021-4034](https://secdb.nttzen.cloud/cve/badge/CVE-2021-4034)](https://secdb.nttzen.cloud/cve/detail/CVE-2021-4034)



## Follina

### [CVE-2022-30190](https://secdb.nttzen.cloud/cve/detail/CVE-2022-30190)

A remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker who successfully exploits this vulnerability can run arbitrary code with the privileges of the calling application. The attacker can then install programs, view, change, or delete data, or create new accounts in the context allowed by the user’s rights.
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

[![CVE-2022-30190](https://secdb.nttzen.cloud/cve/badge/CVE-2022-30190)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-30190)



## BlueBorne

### [CVE-2017-1000251](https://secdb.nttzen.cloud/cve/detail/CVE-2017-1000251)

The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.

[![CVE-2017-1000251](https://secdb.nttzen.cloud/cve/badge/CVE-2017-1000251)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-1000251)

### [CVE-2017-1000250](https://secdb.nttzen.cloud/cve/detail/CVE-2017-1000250)

All versions of the SDP server in BlueZ 5.46 and earlier are vulnerable to an information disclosure vulnerability which allows remote attackers to obtain sensitive information from the bluetoothd process memory. This vulnerability lies in the processing of SDP search attribute requests.

[![CVE-2017-1000250](https://secdb.nttzen.cloud/cve/badge/CVE-2017-1000250)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-1000250)

### [CVE-2017-0785](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0785)

A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.

[![CVE-2017-0785](https://secdb.nttzen.cloud/cve/badge/CVE-2017-0785)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0785)

### [CVE-2017-0781](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0781)

A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146105.

[![CVE-2017-0781](https://secdb.nttzen.cloud/cve/badge/CVE-2017-0781)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0781)

### [CVE-2017-0782](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0782)

A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146237.

[![CVE-2017-0782](https://secdb.nttzen.cloud/cve/badge/CVE-2017-0782)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0782)

### [CVE-2017-0783](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0783)

A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63145701.

[![CVE-2017-0783](https://secdb.nttzen.cloud/cve/badge/CVE-2017-0783)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0783)

### [CVE-2017-8628](https://secdb.nttzen.cloud/cve/detail/CVE-2017-8628)

Microsoft Bluetooth Driver in Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703 allows a spoofing vulnerability due to Microsoft's implementation of the Bluetooth stack, aka "Microsoft Bluetooth Driver Spoofing Vulnerability".

[![CVE-2017-8628](https://secdb.nttzen.cloud/cve/badge/CVE-2017-8628)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-8628)

### [CVE-2017-14315](https://secdb.nttzen.cloud/cve/detail/CVE-2017-14315)

In Apple iOS 7 through 9, due to a BlueBorne flaw in the implementation of LEAP (Low Energy Audio Protocol), a large audio command can be sent to a targeted device and lead to a heap overflow with attacker-controlled data. Since the audio commands sent via LEAP are not properly validated, an attacker can use this overflow to gain full control of the device through the relatively high privileges of the Bluetooth stack in iOS. The attack bypasses Bluetooth access control; however, the default "Bluetooth On" value must be present in Settings.

[![CVE-2017-14315](https://secdb.nttzen.cloud/cve/badge/CVE-2017-14315)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-14315)



## Retbleed

### [CVE-2022-29900](https://secdb.nttzen.cloud/cve/detail/CVE-2022-29900)

Mis-trained branch predictions for return instructions may allow arbitrary speculative code execution under certain microarchitecture-dependent conditions.

[![CVE-2022-29900](https://secdb.nttzen.cloud/cve/badge/CVE-2022-29900)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-29900)

### [CVE-2022-29901](https://secdb.nttzen.cloud/cve/detail/CVE-2022-29901)

Intel microprocessor generations 6 to 8 are affected by a new Spectre variant that is able to bypass their retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can hijack return instructions to achieve arbitrary speculative code execution under certain microarchitecture-dependent conditions.

[![CVE-2022-29901](https://secdb.nttzen.cloud/cve/badge/CVE-2022-29901)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-29901)



## ProxyNotShell

### [CVE-2022-41040](https://secdb.nttzen.cloud/cve/detail/CVE-2022-41040)

Microsoft Exchange Server Elevation of Privilege Vulnerability

[![CVE-2022-41040](https://secdb.nttzen.cloud/cve/badge/CVE-2022-41040)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-41040)

### [CVE-2022-41082](https://secdb.nttzen.cloud/cve/detail/CVE-2022-41082)

Microsoft Exchange Server Remote Code Execution Vulnerability

[![CVE-2022-41082](https://secdb.nttzen.cloud/cve/badge/CVE-2022-41082)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-41082)



## Text4Shell

### [CVE-2022-42889](https://secdb.nttzen.cloud/cve/detail/CVE-2022-42889)

Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

[![CVE-2022-42889](https://secdb.nttzen.cloud/cve/badge/CVE-2022-42889)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-42889)



## Spring4Shell

### [CVE-2022-22965](https://secdb.nttzen.cloud/cve/detail/CVE-2022-22965)

A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

[![CVE-2022-22965](https://secdb.nttzen.cloud/cve/badge/CVE-2022-22965)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-22965)



## SpookySSL

### [CVE-2022-3602](https://secdb.nttzen.cloud/cve/detail/CVE-2022-3602)

A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

[![CVE-2022-3602](https://secdb.nttzen.cloud/cve/badge/CVE-2022-3602)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-3602)

### [CVE-2022-3786](https://secdb.nttzen.cloud/cve/detail/CVE-2022-3786)

A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.

[![CVE-2022-3786](https://secdb.nttzen.cloud/cve/badge/CVE-2022-3786)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-3786)



## StackRot

### [CVE-2023-3269](https://secdb.nttzen.cloud/cve/detail/CVE-2023-3269)

A vulnerability exists in the memory management subsystem of the Linux kernel. The lock handling for accessing and updating virtual memory areas (VMAs) is incorrect, leading to use-after-free problems. This issue can be successfully exploited to execute arbitrary kernel code, escalate containers, and gain root privileges.

[![CVE-2023-3269](https://secdb.nttzen.cloud/cve/badge/CVE-2023-3269)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-3269)



## Zenbleed

### [CVE-2023-20593](https://secdb.nttzen.cloud/cve/detail/CVE-2023-20593)

An issue in “Zen 2” CPUs, under specific microarchitectural circumstances, may allow an attacker to potentially access sensitive information.

[![CVE-2023-20593](https://secdb.nttzen.cloud/cve/badge/CVE-2023-20593)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-20593)



## GameOver(lay)

### [CVE-2023-2640](https://secdb.nttzen.cloud/cve/detail/CVE-2023-2640)

On Ubuntu kernels carrying both c914c0e27eb0 and "UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs", an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

[![CVE-2023-2640](https://secdb.nttzen.cloud/cve/badge/CVE-2023-2640)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-2640)

### [CVE-2023-32629](https://secdb.nttzen.cloud/cve/detail/CVE-2023-32629)

Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

[![CVE-2023-32629](https://secdb.nttzen.cloud/cve/badge/CVE-2023-32629)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-32629)



## Downfall

### [CVE-2022-40982](https://secdb.nttzen.cloud/cve/detail/CVE-2022-40982)

Information exposure through microarchitectural state after transient execution in certain vector execution units for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.

[![CVE-2022-40982](https://secdb.nttzen.cloud/cve/badge/CVE-2022-40982)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-40982)



## EFAIL

### References
- https://efail.de (EFAIL, Official Website)


### [CVE-2017-17688](https://secdb.nttzen.cloud/cve/detail/CVE-2017-17688)

The OpenPGP specification allows a Cipher Feedback Mode (CFB) malleability-gadget attack that can indirectly lead to plaintext exfiltration, aka EFAIL. NOTE: third parties report that this is a problem in applications that mishandle the Modification Detection Code (MDC) feature or accept an obsolete packet type, not a problem in the OpenPGP specification

[![CVE-2017-17688](https://secdb.nttzen.cloud/cve/badge/CVE-2017-17688)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-17688)

### [CVE-2017-17689](https://secdb.nttzen.cloud/cve/detail/CVE-2017-17689)

The S/MIME specification allows a Cipher Block Chaining (CBC) malleability-gadget attack that can indirectly lead to plaintext exfiltration, aka EFAIL.

[![CVE-2017-17689](https://secdb.nttzen.cloud/cve/badge/CVE-2017-17689)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-17689)



## Dirty COW

### [CVE-2016-5195](https://secdb.nttzen.cloud/cve/detail/CVE-2016-5195)

Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

[![CVE-2016-5195](https://secdb.nttzen.cloud/cve/badge/CVE-2016-5195)](https://secdb.nttzen.cloud/cve/detail/CVE-2016-5195)



## DROWN

### [CVE-2016-0800](https://secdb.nttzen.cloud/cve/detail/CVE-2016-0800)

The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a "DROWN" attack.

[![CVE-2016-0800](https://secdb.nttzen.cloud/cve/badge/CVE-2016-0800)](https://secdb.nttzen.cloud/cve/detail/CVE-2016-0800)



## SigSpoof

### [CVE-2018-12020](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12020)

mainproc.c in GnuPG before 2.2.8 mishandles the original filename during decryption and verification actions, which allows remote attackers to spoof the output that GnuPG sends on file descriptor 2 to other programs that use the "--status-fd 2" option. For example, the OpenPGP data might represent an original filename that contains line feed characters in conjunction with GOODSIG or VALIDSIG status codes.

[![CVE-2018-12020](https://secdb.nttzen.cloud/cve/badge/CVE-2018-12020)](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12020)



## Foreshadow

### [CVE-2018-3615](https://secdb.nttzen.cloud/cve/detail/CVE-2018-3615)

Systems with microprocessors utilizing speculative execution and Intel software guard extensions (Intel SGX) may allow unauthorized disclosure of information residing in the L1 data cache from an enclave to an attacker with local user access via a side-channel analysis.

[![CVE-2018-3615](https://secdb.nttzen.cloud/cve/badge/CVE-2018-3615)](https://secdb.nttzen.cloud/cve/detail/CVE-2018-3615)

### [CVE-2018-3620](https://secdb.nttzen.cloud/cve/detail/CVE-2018-3620)

Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access via a terminal page fault and a side-channel analysis.

[![CVE-2018-3620](https://secdb.nttzen.cloud/cve/badge/CVE-2018-3620)](https://secdb.nttzen.cloud/cve/detail/CVE-2018-3620)

### [CVE-2018-3646](https://secdb.nttzen.cloud/cve/detail/CVE-2018-3646)

Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access with guest OS privilege via a terminal page fault and a side-channel analysis.

[![CVE-2018-3646](https://secdb.nttzen.cloud/cve/badge/CVE-2018-3646)](https://secdb.nttzen.cloud/cve/detail/CVE-2018-3646)



## ROCA

### [CVE-2017-15361](https://secdb.nttzen.cloud/cve/detail/CVE-2017-15361)

The Infineon RSA library 1.02.013 in Infineon Trusted Platform Module (TPM) firmware, such as versions before 0000000000000422 - 4.34, before 000000000000062b - 6.43, and before 0000000000008521 - 133.33, mishandles RSA key generation, which makes it easier for attackers to defeat various cryptographic protection mechanisms via targeted attacks, aka ROCA. Examples of affected technologies include BitLocker with TPM 1.2, YubiKey 4 (before 4.3.5) PGP key generation, and the Cached User Data encryption feature in Chrome OS.

[![CVE-2017-15361](https://secdb.nttzen.cloud/cve/badge/CVE-2017-15361)](https://secdb.nttzen.cloud/cve/detail/CVE-2017-15361)



## Microarchitectural Data Sampling (MDS)

### [CVE-2018-12130](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12130)

Microarchitectural Fill Buffer Data Sampling (MFBDS): Fill buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. A list of impacted products can be found here: https://www.intel.com/content/dam/www/public/us/en/documents/corporate-information/SA00233-microcode-update-guidance_05132019.pdf

[![CVE-2018-12130](https://secdb.nttzen.cloud/cve/badge/CVE-2018-12130)](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12130)

### [CVE-2018-12126](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12126)

Microarchitectural Store Buffer Data Sampling (MSBDS): Store buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. A list of impacted products can be found here: https://www.intel.com/content/dam/www/public/us/en/documents/corporate-information/SA00233-microcode-update-guidance_05132019.pdf

[![CVE-2018-12126](https://secdb.nttzen.cloud/cve/badge/CVE-2018-12126)](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12126)

### [CVE-2018-12127](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12127)

Microarchitectural Load Port Data Sampling (MLPDS): Load ports on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. A list of impacted products can be found here: https://www.intel.com/content/dam/www/public/us/en/documents/corporate-information/SA00233-microcode-update-guidance_05132019.pdf

[![CVE-2018-12127](https://secdb.nttzen.cloud/cve/badge/CVE-2018-12127)](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12127)

### [CVE-2019-11091](https://secdb.nttzen.cloud/cve/detail/CVE-2019-11091)

Microarchitectural Data Sampling Uncacheable Memory (MDSUM): Uncacheable memory on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. A list of impacted products can be found here: https://www.intel.com/content/dam/www/public/us/en/documents/corporate-information/SA00233-microcode-update-guidance_05132019.pdf

[![CVE-2019-11091](https://secdb.nttzen.cloud/cve/badge/CVE-2019-11091)](https://secdb.nttzen.cloud/cve/detail/CVE-2019-11091)



## Looney Tunables

### [CVE-2023-4911](https://secdb.nttzen.cloud/cve/detail/CVE-2023-4911)

A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

[![CVE-2023-4911](https://secdb.nttzen.cloud/cve/badge/CVE-2023-4911)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-4911)



## HTTP/2 Rapid Reset Attack

### [CVE-2023-44487](https://secdb.nttzen.cloud/cve/detail/CVE-2023-44487)

The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

[![CVE-2023-44487](https://secdb.nttzen.cloud/cve/badge/CVE-2023-44487)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-44487)



## Reptar

### [CVE-2023-23583](https://secdb.nttzen.cloud/cve/detail/CVE-2023-23583)

Sequence of processor instructions leads to unexpected behavior for some Intel(R) Processors may allow an authenticated user to potentially enable escalation of privilege and/or information disclosure and/or denial of service via local access.

[![CVE-2023-23583](https://secdb.nttzen.cloud/cve/badge/CVE-2023-23583)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-23583)



## Dirty Pipe

### References
- https://dirtypipe.cm4all.com (The Dirty Pipe Vulnerability, Official Website)


### [CVE-2022-0847](https://secdb.nttzen.cloud/cve/detail/CVE-2022-0847)

A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

[![CVE-2022-0847](https://secdb.nttzen.cloud/cve/badge/CVE-2022-0847)](https://secdb.nttzen.cloud/cve/detail/CVE-2022-0847)



## Terrapin

### [CVE-2023-48795](https://secdb.nttzen.cloud/cve/detail/CVE-2023-48795)

The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

[![CVE-2023-48795](https://secdb.nttzen.cloud/cve/badge/CVE-2023-48795)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-48795)



## KeyTrap

### [CVE-2023-50387](https://secdb.nttzen.cloud/cve/detail/CVE-2023-50387)

Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote attackers to cause a denial of service (CPU consumption) via one or more DNSSEC responses, aka the "KeyTrap" issue. One of the concerns is that, when there is a zone with many DNSKEY and RRSIG records, the protocol specification implies that an algorithm must evaluate all combinations of DNSKEY and RRSIG records.

[![CVE-2023-50387](https://secdb.nttzen.cloud/cve/badge/CVE-2023-50387)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-50387)



## Wall-Escape

### [CVE-2024-28085](https://secdb.nttzen.cloud/cve/detail/CVE-2024-28085)

wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.

[![CVE-2024-28085](https://secdb.nttzen.cloud/cve/badge/CVE-2024-28085)](https://secdb.nttzen.cloud/cve/detail/CVE-2024-28085)



## Flipping Pages

### [CVE-2024-1086](https://secdb.nttzen.cloud/cve/detail/CVE-2024-1086)

A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation.

The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT.

We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

[![CVE-2024-1086](https://secdb.nttzen.cloud/cve/badge/CVE-2024-1086)](https://secdb.nttzen.cloud/cve/detail/CVE-2024-1086)



## TunnelVision

### [CVE-2024-3661](https://secdb.nttzen.cloud/cve/detail/CVE-2024-3661)

DHCP can add routes to a client’s routing table via the classless static route option (121). VPN-based security solutions that rely on routes to redirect traffic can be forced to leak traffic over the physical interface. An attacker on the same local network can read, disrupt, or possibly modify network traffic that was expected to be protected by the VPN.

[![CVE-2024-3661](https://secdb.nttzen.cloud/cve/badge/CVE-2024-3661)](https://secdb.nttzen.cloud/cve/detail/CVE-2024-3661)



## SSID Confusion Attack

### [CVE-2023-52424](https://secdb.nttzen.cloud/cve/detail/CVE-2023-52424)

The IEEE 802.11 standard sometimes enables an adversary to trick a victim into connecting to an unintended or untrusted network with Home WEP, Home WPA3 SAE-loop. Enterprise 802.1X/EAP, Mesh AMPE, or FILS, aka an "SSID Confusion" issue. This occurs because the SSID is not always used to derive the pairwise master key or session keys, and because there is not a protected exchange of an SSID during a 4-way handshake.

[![CVE-2023-52424](https://secdb.nttzen.cloud/cve/badge/CVE-2023-52424)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-52424)



## regreSSHion

### [CVE-2024-6387](https://secdb.nttzen.cloud/cve/detail/CVE-2024-6387)

A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

[![CVE-2024-6387](https://secdb.nttzen.cloud/cve/badge/CVE-2024-6387)](https://secdb.nttzen.cloud/cve/detail/CVE-2024-6387)



## ShellTorch

### [CVE-2023-43654](https://secdb.nttzen.cloud/cve/detail/CVE-2023-43654)

TorchServe is a tool for serving and scaling PyTorch models in production. TorchServe default configuration lacks proper input validation, enabling third parties to invoke remote HTTP download requests and write files to the disk. This issue could be taken advantage of to compromise the integrity of the system and sensitive data. This issue is present in versions 0.1.0 to 0.8.1. A user is able to load the model of their choice from any URL that they would like to use. The user of TorchServe is responsible for configuring both the allowed_urls and specifying the model URL to be used. A pull request to warn the user when the default value for allowed_urls is used has been merged in PR #2534. TorchServe release 0.8.2 includes this change. Users are advised to upgrade. There are no known workarounds for this issue.

[![CVE-2023-43654](https://secdb.nttzen.cloud/cve/badge/CVE-2023-43654)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-43654)



## MadLicense

### [CVE-2024-38077](https://secdb.nttzen.cloud/cve/detail/CVE-2024-38077)

Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability

[![CVE-2024-38077](https://secdb.nttzen.cloud/cve/badge/CVE-2024-38077)](https://secdb.nttzen.cloud/cve/detail/CVE-2024-38077)



## Copy2Pwn

### [CVE-2024-38213](https://secdb.nttzen.cloud/cve/detail/CVE-2024-38213)

Windows Mark of the Web Security Feature Bypass Vulnerability

[![CVE-2024-38213](https://secdb.nttzen.cloud/cve/badge/CVE-2024-38213)](https://secdb.nttzen.cloud/cve/detail/CVE-2024-38213)



## LDAP Nightmare

### [CVE-2024-49112](https://secdb.nttzen.cloud/cve/detail/CVE-2024-49112)

Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability

[![CVE-2024-49112](https://secdb.nttzen.cloud/cve/badge/CVE-2024-49112)](https://secdb.nttzen.cloud/cve/detail/CVE-2024-49112)

### [CVE-2024-49113](https://secdb.nttzen.cloud/cve/detail/CVE-2024-49113)

Windows Lightweight Directory Access Protocol (LDAP) Denial of Service Vulnerability

[![CVE-2024-49113](https://secdb.nttzen.cloud/cve/badge/CVE-2024-49113)](https://secdb.nttzen.cloud/cve/detail/CVE-2024-49113)



## LogoFAIL

### [CVE-2023-40238](https://secdb.nttzen.cloud/cve/detail/CVE-2023-40238)

A LogoFAIL issue was discovered in BmpDecoderDxe in Insyde InsydeH2O with kernel 5.2 before 05.28.47, 5.3 before 05.37.47, 5.4 before 05.45.47, 5.5 before 05.53.47, and 5.6 before 05.60.47 for certain Lenovo devices. Image parsing of crafted BMP logo files can copy data to a specific address during the DXE phase of UEFI execution. This occurs because of an integer signedness error involving PixelHeight and PixelWidth during RLE4/RLE8 compression.

[![CVE-2023-40238](https://secdb.nttzen.cloud/cve/badge/CVE-2023-40238)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-40238)



## IngressNightmare

### [CVE-2025-1097](https://secdb.nttzen.cloud/cve/detail/CVE-2025-1097)

A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-tls-match-cn` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

[![CVE-2025-1097](https://secdb.nttzen.cloud/cve/badge/CVE-2025-1097)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-1097)

### [CVE-2025-1098](https://secdb.nttzen.cloud/cve/detail/CVE-2025-1098)

A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `mirror-target` and `mirror-host` Ingress annotations can be used to inject arbitrary configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

[![CVE-2025-1098](https://secdb.nttzen.cloud/cve/badge/CVE-2025-1098)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-1098)

### [CVE-2025-1974](https://secdb.nttzen.cloud/cve/detail/CVE-2025-1974)

A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

[![CVE-2025-1974](https://secdb.nttzen.cloud/cve/badge/CVE-2025-1974)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-1974)

### [CVE-2025-24513](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24513)

A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where attacker-provided data are included in a filename by the ingress-nginx Admission Controller feature, resulting in directory traversal within the container. This could result in denial of service, or when combined with other vulnerabilities, limited disclosure of Secret objects from the cluster.

[![CVE-2025-24513](https://secdb.nttzen.cloud/cve/badge/CVE-2025-24513)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24513)

### [CVE-2025-24514](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24514)

A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-url` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

[![CVE-2025-24514](https://secdb.nttzen.cloud/cve/badge/CVE-2025-24514)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24514)



## chwoot

### [CVE-2025-32463](https://secdb.nttzen.cloud/cve/detail/CVE-2025-32463)

Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

[![CVE-2025-32463](https://secdb.nttzen.cloud/cve/badge/CVE-2025-32463)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-32463)



## CitrixBleed

### [CVE-2023-4966](https://secdb.nttzen.cloud/cve/detail/CVE-2023-4966)

Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA  virtual server.

[![CVE-2023-4966](https://secdb.nttzen.cloud/cve/badge/CVE-2023-4966)](https://secdb.nttzen.cloud/cve/detail/CVE-2023-4966)



## CitrixBleed 2

### [CVE-2025-5777](https://secdb.nttzen.cloud/cve/detail/CVE-2025-5777)

Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

[![CVE-2025-5777](https://secdb.nttzen.cloud/cve/badge/CVE-2025-5777)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-5777)



## ToolShell

### [CVE-2025-49706](https://secdb.nttzen.cloud/cve/detail/CVE-2025-49706)

Improper authentication in Microsoft Office SharePoint allows an unauthorized attacker to perform spoofing over a network.

[![CVE-2025-49706](https://secdb.nttzen.cloud/cve/badge/CVE-2025-49706)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-49706)

### [CVE-2025-49704](https://secdb.nttzen.cloud/cve/detail/CVE-2025-49704)

Improper control of generation of code ('code injection') in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.

[![CVE-2025-49704](https://secdb.nttzen.cloud/cve/badge/CVE-2025-49704)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-49704)

### [CVE-2025-53770](https://secdb.nttzen.cloud/cve/detail/CVE-2025-53770)

Deserialization of untrusted data in on-premises Microsoft SharePoint Server allows an unauthorized attacker to execute code over a network.
Microsoft is aware that an exploit for CVE-2025-53770 exists in the wild.
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

[![CVE-2025-53770](https://secdb.nttzen.cloud/cve/badge/CVE-2025-53770)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-53770)

### [CVE-2025-53771](https://secdb.nttzen.cloud/cve/detail/CVE-2025-53771)

Improper authentication in Microsoft Office SharePoint allows an unauthorized attacker to perform spoofing over a network.

[![CVE-2025-53771](https://secdb.nttzen.cloud/cve/badge/CVE-2025-53771)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-53771)



## ReVault

### [CVE-2025-24311](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24311)

An out-of-bounds read vulnerability exists in the cv_send_blockdata 
functionality of Dell ControlVault3 prior to 5.15.10.14 and Dell ControlVault3 Plus prior to 6.2.26.36. A specially crafted 
ControlVault API call can lead to an information leak. An attacker can 
issue an API call to trigger this vulnerability.

[![CVE-2025-24311](https://secdb.nttzen.cloud/cve/badge/CVE-2025-24311)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24311)

### [CVE-2025-25050](https://secdb.nttzen.cloud/cve/detail/CVE-2025-25050)

An out-of-bounds write vulnerability exists in the 
cv_upgrade_sensor_firmware functionality of Dell ControlVault3 prior to 5.15.10.14 and Dell ControlVault 3 Plus prior to 6.2.26.36.
 A specially crafted ControlVault API call can lead to an out-of-bounds 
write. An attacker can issue an API call to trigger this vulnerability.

[![CVE-2025-25050](https://secdb.nttzen.cloud/cve/badge/CVE-2025-25050)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-25050)

### [CVE-2025-25215](https://secdb.nttzen.cloud/cve/detail/CVE-2025-25215)

An arbitrary free vulnerability exists in the cv_close functionality of 
Dell ControlVault3 prior to 5.15.10.14 and Dell ControlVault3 Plus prior to 6.2.26.36. A specially crafted ControlVault API call 
can lead to an arbitrary free. An attacker can forge a fake session to 
trigger this vulnerability.

[![CVE-2025-25215](https://secdb.nttzen.cloud/cve/badge/CVE-2025-25215)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-25215)

### [CVE-2025-24922](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24922)

A stack-based buffer overflow vulnerability exists in the 
securebio_identify functionality of Dell ControlVault3 prior to 5.15.10.14 and Dell ControlVault3 Plus prior to 6.2.26.36. A 
specially crafted malicious cv_object can lead to a arbitrary code 
execution. An attacker can issue an API call to trigger this 
vulnerability.

[![CVE-2025-24922](https://secdb.nttzen.cloud/cve/badge/CVE-2025-24922)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24922)

### [CVE-2025-24919](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24919)

A deserialization of untrusted input vulnerability exists in the cvhDecapsulateCmd functionality of Dell ControlVault3 prior to 5.15.10.14 and ControlVault3 Plus prior to 6.2.26.36. A specially crafted ControlVault response to a command can lead to arbitrary code execution. An attacker can compromise a ControlVault firmware and have it craft a malicious response to trigger this vulnerability.

[![CVE-2025-24919](https://secdb.nttzen.cloud/cve/badge/CVE-2025-24919)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-24919)



## TARmageddon

### References
- https://edera.dev/stories/tarmageddon (TARmageddon (CVE-2025-62518): RCE Vulnerability Highlights the Challenges of Open Source Abandonware, Edera)


### [CVE-2025-62518](https://secdb.nttzen.cloud/cve/detail/CVE-2025-62518)

astral-tokio-tar is a tar archive reading/writing library for async Rust. Versions of astral-tokio-tar prior to 0.5.6 contain a boundary parsing vulnerability that allows attackers to smuggle additional archive entries by exploiting inconsistent PAX/ustar header handling. When processing archives with PAX-extended headers containing size overrides, the parser incorrectly advances stream position based on ustar header size (often zero) instead of the PAX-specified size, causing it to interpret file content as legitimate tar headers. This issue has been patched in version 0.5.6. There are no workarounds.

[![CVE-2025-62518](https://secdb.nttzen.cloud/cve/badge/CVE-2025-62518)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-62518)



## React2Shell

### References
- https://react2shell.com/ (React2Shell (CVE-2025-55182), Official Website)


### [CVE-2025-55182](https://secdb.nttzen.cloud/cve/detail/CVE-2025-55182)

A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

[![CVE-2025-55182](https://secdb.nttzen.cloud/cve/badge/CVE-2025-55182)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-55182)



## Mongobleed

### [CVE-2025-14847](https://secdb.nttzen.cloud/cve/detail/CVE-2025-14847)

Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

[![CVE-2025-14847](https://secdb.nttzen.cloud/cve/badge/CVE-2025-14847)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-14847)



## Ni8mare

### References
- https://www.cyera.com/research-labs/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858 (Ni8mare - Unauthenticated Remote Code Execution in n8n (CVE-2026-21858), Research)


### [CVE-2026-21858](https://secdb.nttzen.cloud/cve/detail/CVE-2026-21858)

n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

[![CVE-2026-21858](https://secdb.nttzen.cloud/cve/badge/CVE-2026-21858)](https://secdb.nttzen.cloud/cve/detail/CVE-2026-21858)



## WhisperPair

### [CVE-2025-36911](https://secdb.nttzen.cloud/cve/detail/CVE-2025-36911)

In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

[![CVE-2025-36911](https://secdb.nttzen.cloud/cve/badge/CVE-2025-36911)](https://secdb.nttzen.cloud/cve/detail/CVE-2025-36911)



