# SecDB - Security Feeds
Security feeds for SecDB (https://secdb.nttzen.cloud)

## Log4Shell

### References
- https://en.wikipedia.org/wiki/Log4Shell (Log4Shell, Wikipedia)
- https://log4shell.com (Log4Shell, Official Website)


### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2021-44228](https://secdb.nttzen.cloud/cve/detail/CVE-2021-44228) | Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects. |


## ShellShock

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2014-6271](https://secdb.nttzen.cloud/cve/detail/CVE-2014-6271) | GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix. |
| [CVE-2014-6277](https://secdb.nttzen.cloud/cve/detail/CVE-2014-6277) | GNU Bash through 4.3 bash43-026 does not properly parse function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code or cause a denial of service (uninitialized memory access, and untrusted-pointer read and write operations) via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271 and CVE-2014-7169. |
| [CVE-2014-6278](https://secdb.nttzen.cloud/cve/detail/CVE-2014-6278) | GNU Bash through 4.3 bash43-026 does not properly parse function definitions in the values of environment variables, which allows remote attackers to execute arbitrary commands via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271, CVE-2014-7169, and CVE-2014-6277. |
| [CVE-2014-7169](https://secdb.nttzen.cloud/cve/detail/CVE-2014-7169) | GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in the values of environment variables, which allows remote attackers to write to files or possibly have unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271. |
| [CVE-2014-7186](https://secdb.nttzen.cloud/cve/detail/CVE-2014-7186) | The redirection implementation in parse.y in GNU Bash through 4.3 bash43-026 allows remote attackers to cause a denial of service (out-of-bounds array access and application crash) or possibly have unspecified other impact via crafted use of here documents, aka the "redir_stack" issue. |
| [CVE-2014-7187](https://secdb.nttzen.cloud/cve/detail/CVE-2014-7187) | Off-by-one error in the read_token_word function in parse.y in GNU Bash through 4.3 bash43-026 allows remote attackers to cause a denial of service (out-of-bounds array access and application crash) or possibly have unspecified other impact via deeply nested for loops, aka the "word_lineno" issue. |


## Heartbleed

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2014-0160](https://secdb.nttzen.cloud/cve/detail/CVE-2014-0160) | The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug. |


## BlueKeep

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2019-0708](https://secdb.nttzen.cloud/cve/detail/CVE-2019-0708) | A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'. |


## Meltdown

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2017-5754](https://secdb.nttzen.cloud/cve/detail/CVE-2017-5754) | Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache. |


## Spectre

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2017-5753](https://secdb.nttzen.cloud/cve/detail/CVE-2017-5753) | Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis. |
| [CVE-2017-5715](https://secdb.nttzen.cloud/cve/detail/CVE-2017-5715) | Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis. |


## EternalBlue

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2017-0144](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0144) | The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148. |


## POODLE

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2014-3566](https://secdb.nttzen.cloud/cve/detail/CVE-2014-3566) | The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other products, uses nondeterministic CBC padding, which makes it easier for man-in-the-middle attackers to obtain cleartext data via a padding-oracle attack, aka the "POODLE" issue. |


## SMBGhost

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2020-0796](https://secdb.nttzen.cloud/cve/detail/CVE-2020-0796) | A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'. |


## PrintNightmare

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2021-1675](https://secdb.nttzen.cloud/cve/detail/CVE-2021-1675) | Windows Print Spooler Remote Code Execution Vulnerability |
| [CVE-2021-34527](https://secdb.nttzen.cloud/cve/detail/CVE-2021-34527) | <p>A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.</p>
<p>UPDATE July 7, 2021: The security update for Windows Server 2012, Windows Server 2016 and Windows 10, Version 1607 have been released. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability.</p>
<p>In addition to installing the updates, in order to secure your system, you must confirm that the following registry settings are set to 0 (zero) or are not defined (<strong>Note</strong>: These registry keys do not exist by default, and therefore are already at the secure setting.), also that your Group Policy setting are correct (see FAQ):</p>
<ul>
<li>HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint</li>
<li>NoWarningNoElevationOnInstall = 0 (DWORD) or not defined (default setting)</li>
<li>UpdatePromptSettings = 0 (DWORD) or not defined (default setting)</li>
</ul>
<p><strong>Having NoWarningNoElevationOnInstall set to 1 makes your system vulnerable by design.</strong></p>
<p>UPDATE July 6, 2021: Microsoft has completed the investigation and has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability. See also <a href="https://support.microsoft.com/topic/31b91c02-05bc-4ada-a7ea-183b129578a7">KB5005010: Restricting installation of new printer drivers after applying the July 6, 2021 updates</a>.</p>
<p>Note that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527.</p> |


## KRACK

### References
- https://en.wikipedia.org/wiki/KRACK (KRACK, Wikipedia)


### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2017-13077](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13077) | Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Pairwise Transient Key (PTK) Temporal Key (TK) during the four-way handshake, allowing an attacker within radio range to replay, decrypt, or spoof frames. |
| [CVE-2017-13078](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13078) | Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Group Temporal Key (GTK) during the four-way handshake, allowing an attacker within radio range to replay frames from access points to clients. |
| [CVE-2017-13079](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13079) | Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity Group Temporal Key (IGTK) during the four-way handshake, allowing an attacker within radio range to spoof frames from access points to clients. |
| [CVE-2017-13080](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13080) | Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Group Temporal Key (GTK) during the group key handshake, allowing an attacker within radio range to replay frames from access points to clients. |
| [CVE-2017-13081](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13081) | Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity Group Temporal Key (IGTK) during the group key handshake, allowing an attacker within radio range to spoof frames from access points to clients. |
| [CVE-2017-13082](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13082) | Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11r allows reinstallation of the Pairwise Transient Key (PTK) Temporal Key (TK) during the fast BSS transmission (FT) handshake, allowing an attacker within radio range to replay, decrypt, or spoof frames. |
| [CVE-2017-13084](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13084) | Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Station-To-Station-Link (STSL) Transient Key (STK) during the PeerKey handshake, allowing an attacker within radio range to replay, decrypt, or spoof frames. |
| [CVE-2017-13086](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13086) | Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Tunneled Direct-Link Setup (TDLS) Peer Key (TPK) during the TDLS handshake, allowing an attacker within radio range to replay, decrypt, or spoof frames. |
| [CVE-2017-13087](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13087) | Wi-Fi Protected Access (WPA and WPA2) that support 802.11v allows reinstallation of the Group Temporal Key (GTK) when processing a Wireless Network Management (WNM) Sleep Mode Response frame, allowing an attacker within radio range to replay frames from access points to clients. |
| [CVE-2017-13088](https://secdb.nttzen.cloud/cve/detail/CVE-2017-13088) | Wi-Fi Protected Access (WPA and WPA2) that support 802.11v allows reinstallation of the Integrity Group Temporal Key (IGTK) when processing a Wireless Network Management (WNM) Sleep Mode Response frame, allowing an attacker within radio range to replay frames from access points to clients. |


## PwnKit

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2021-4034](https://secdb.nttzen.cloud/cve/detail/CVE-2021-4034) | A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine. |


## Follina

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2022-30190](https://secdb.nttzen.cloud/cve/detail/CVE-2022-30190) | <p>A remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker who successfully exploits this vulnerability can run arbitrary code with the privileges of the calling application. The attacker can then install programs, view, change, or delete data, or create new accounts in the context allowed by the user’s rights.</p>
<p>Please see the <a href="https://aka.ms/CVE-2022-30190-Guidance">MSRC Blog Entry</a> for important information about steps you can take to protect your system from this vulnerability.</p> |


## BlueBorne

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2017-1000251](https://secdb.nttzen.cloud/cve/detail/CVE-2017-1000251) | The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space. |
| [CVE-2017-1000250](https://secdb.nttzen.cloud/cve/detail/CVE-2017-1000250) | All versions of the SDP server in BlueZ 5.46 and earlier are vulnerable to an information disclosure vulnerability which allows remote attackers to obtain sensitive information from the bluetoothd process memory. This vulnerability lies in the processing of SDP search attribute requests. |
| [CVE-2017-0785](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0785) | A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698. |
| [CVE-2017-0781](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0781) | A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146105. |
| [CVE-2017-0782](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0782) | A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146237. |
| [CVE-2017-0783](https://secdb.nttzen.cloud/cve/detail/CVE-2017-0783) | A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63145701. |
| [CVE-2017-8628](https://secdb.nttzen.cloud/cve/detail/CVE-2017-8628) | Microsoft Bluetooth Driver in Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703 allows a spoofing vulnerability due to Microsoft's implementation of the Bluetooth stack, aka "Microsoft Bluetooth Driver Spoofing Vulnerability". |
| [CVE-2017-14315](https://secdb.nttzen.cloud/cve/detail/CVE-2017-14315) | In Apple iOS 7 through 9, due to a BlueBorne flaw in the implementation of LEAP (Low Energy Audio Protocol), a large audio command can be sent to a targeted device and lead to a heap overflow with attacker-controlled data. Since the audio commands sent via LEAP are not properly validated, an attacker can use this overflow to gain full control of the device through the relatively high privileges of the Bluetooth stack in iOS. The attack bypasses Bluetooth access control; however, the default "Bluetooth On" value must be present in Settings. |


## Retbleed

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2022-29900](https://secdb.nttzen.cloud/cve/detail/CVE-2022-29900) | Mis-trained branch predictions for return instructions may allow arbitrary speculative code execution under certain microarchitecture-dependent conditions. |
| [CVE-2022-29901](https://secdb.nttzen.cloud/cve/detail/CVE-2022-29901) | Intel microprocessor generations 6 to 8 are affected by a new Spectre variant that is able to bypass their retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can hijack return instructions to achieve arbitrary speculative code execution under certain microarchitecture-dependent conditions. |


## ProxyNotShell

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2022-41040](https://secdb.nttzen.cloud/cve/detail/CVE-2022-41040) | Microsoft Exchange Server Elevation of Privilege Vulnerability |
| [CVE-2022-41082](https://secdb.nttzen.cloud/cve/detail/CVE-2022-41082) | Microsoft Exchange Server Remote Code Execution Vulnerability |


## Text4Shell

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2022-42889](https://secdb.nttzen.cloud/cve/detail/CVE-2022-42889) | Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default. |


## Spring4Shell

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2022-22965](https://secdb.nttzen.cloud/cve/detail/CVE-2022-22965) | A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it. |


## SpookySSL

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2022-3602](https://secdb.nttzen.cloud/cve/detail/CVE-2022-3602) | A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6). |
| [CVE-2022-3786](https://secdb.nttzen.cloud/cve/detail/CVE-2022-3786) | A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. |


## StackRot

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2023-3269](https://secdb.nttzen.cloud/cve/detail/CVE-2023-3269) | A vulnerability exists in the memory management subsystem of the Linux kernel. The lock handling for accessing and updating virtual memory areas (VMAs) is incorrect, leading to use-after-free problems. This issue can be successfully exploited to execute arbitrary kernel code, escalate containers, and gain root privileges. |


## Zenbleed

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2023-20593](https://secdb.nttzen.cloud/cve/detail/CVE-2023-20593) | An issue in “Zen 2” CPUs, under specific microarchitectural circumstances, may allow an attacker to potentially access sensitive information. |


## GameOver(lay)

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2023-2640](https://secdb.nttzen.cloud/cve/detail/CVE-2023-2640) | On Ubuntu kernels carrying both c914c0e27eb0 and "UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs", an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks. |
| [CVE-2023-32629](https://secdb.nttzen.cloud/cve/detail/CVE-2023-32629) | Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels |


## Downfall

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2022-40982](https://secdb.nttzen.cloud/cve/detail/CVE-2022-40982) | Information exposure through microarchitectural state after transient execution in certain vector execution units for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access. |


## EFAIL

### References
- https://efail.de (EFAIL, Official Website)


### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2017-17688](https://secdb.nttzen.cloud/cve/detail/CVE-2017-17688) | The OpenPGP specification allows a Cipher Feedback Mode (CFB) malleability-gadget attack that can indirectly lead to plaintext exfiltration, aka EFAIL. NOTE: third parties report that this is a problem in applications that mishandle the Modification Detection Code (MDC) feature or accept an obsolete packet type, not a problem in the OpenPGP specification |
| [CVE-2017-17689](https://secdb.nttzen.cloud/cve/detail/CVE-2017-17689) | The S/MIME specification allows a Cipher Block Chaining (CBC) malleability-gadget attack that can indirectly lead to plaintext exfiltration, aka EFAIL. |


## Dirty COW

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2016-5195](https://secdb.nttzen.cloud/cve/detail/CVE-2016-5195) | Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW." |


## DROWN

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2016-0800](https://secdb.nttzen.cloud/cve/detail/CVE-2016-0800) | The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a "DROWN" attack. |


## SigSpoof

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2018-12020](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12020) | mainproc.c in GnuPG before 2.2.8 mishandles the original filename during decryption and verification actions, which allows remote attackers to spoof the output that GnuPG sends on file descriptor 2 to other programs that use the "--status-fd 2" option. For example, the OpenPGP data might represent an original filename that contains line feed characters in conjunction with GOODSIG or VALIDSIG status codes. |


## Foreshadow

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2018-3615](https://secdb.nttzen.cloud/cve/detail/CVE-2018-3615) | Systems with microprocessors utilizing speculative execution and Intel software guard extensions (Intel SGX) may allow unauthorized disclosure of information residing in the L1 data cache from an enclave to an attacker with local user access via a side-channel analysis. |
| [CVE-2018-3620](https://secdb.nttzen.cloud/cve/detail/CVE-2018-3620) | Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access via a terminal page fault and a side-channel analysis. |
| [CVE-2018-3646](https://secdb.nttzen.cloud/cve/detail/CVE-2018-3646) | Systems with microprocessors utilizing speculative execution and address translations may allow unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access with guest OS privilege via a terminal page fault and a side-channel analysis. |


## ROCA

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2017-15361](https://secdb.nttzen.cloud/cve/detail/CVE-2017-15361) | The Infineon RSA library 1.02.013 in Infineon Trusted Platform Module (TPM) firmware, such as versions before 0000000000000422 - 4.34, before 000000000000062b - 6.43, and before 0000000000008521 - 133.33, mishandles RSA key generation, which makes it easier for attackers to defeat various cryptographic protection mechanisms via targeted attacks, aka ROCA. Examples of affected technologies include BitLocker with TPM 1.2, YubiKey 4 (before 4.3.5) PGP key generation, and the Cached User Data encryption feature in Chrome OS. |


## Microarchitectural Data Sampling (MDS)

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2018-12130](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12130) | Microarchitectural Fill Buffer Data Sampling (MFBDS): Fill buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. A list of impacted products can be found here: https://www.intel.com/content/dam/www/public/us/en/documents/corporate-information/SA00233-microcode-update-guidance_05132019.pdf |
| [CVE-2018-12126](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12126) | Microarchitectural Store Buffer Data Sampling (MSBDS): Store buffers on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. A list of impacted products can be found here: https://www.intel.com/content/dam/www/public/us/en/documents/corporate-information/SA00233-microcode-update-guidance_05132019.pdf |
| [CVE-2018-12127](https://secdb.nttzen.cloud/cve/detail/CVE-2018-12127) | Microarchitectural Load Port Data Sampling (MLPDS): Load ports on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. A list of impacted products can be found here: https://www.intel.com/content/dam/www/public/us/en/documents/corporate-information/SA00233-microcode-update-guidance_05132019.pdf |
| [CVE-2019-11091](https://secdb.nttzen.cloud/cve/detail/CVE-2019-11091) | Microarchitectural Data Sampling Uncacheable Memory (MDSUM): Uncacheable memory on some microprocessors utilizing speculative execution may allow an authenticated user to potentially enable information disclosure via a side channel with local access. A list of impacted products can be found here: https://www.intel.com/content/dam/www/public/us/en/documents/corporate-information/SA00233-microcode-update-guidance_05132019.pdf |


## Looney Tunables

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2023-4911](https://secdb.nttzen.cloud/cve/detail/CVE-2023-4911) | A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges. |


## HTTP/2 Rapid Reset Attack

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2023-44487](https://secdb.nttzen.cloud/cve/detail/CVE-2023-44487) | The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023. |


## Reptar

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2023-23583](https://secdb.nttzen.cloud/cve/detail/CVE-2023-23583) | Sequence of processor instructions leads to unexpected behavior for some Intel(R) Processors may allow an authenticated user to potentially enable escalation of privilege and/or information disclosure and/or denial of service via local access. |


## Dirty Pipe

### References
- https://dirtypipe.cm4all.com (The Dirty Pipe Vulnerability, Official Website)


### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2022-0847](https://secdb.nttzen.cloud/cve/detail/CVE-2022-0847) | A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system. |


## Terrapin

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2023-48795](https://secdb.nttzen.cloud/cve/detail/CVE-2023-48795) | The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust. |


## KeyTrap

### CVEs

| CVE | Description |
| --- | --- |
| [CVE-2023-50387](https://secdb.nttzen.cloud/cve/detail/CVE-2023-50387) | Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote attackers to cause a denial of service (CPU consumption) via one or more DNSSEC responses, aka the "KeyTrap" issue. One of the concerns is that, when there is a zone with many DNSKEY and RRSIG records, the protocol specification implies that an algorithm must evaluate all combinations of DNSKEY and RRSIG records. |



