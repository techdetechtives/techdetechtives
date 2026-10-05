/*
  TechDetechtives threat rules for files carved from network traffic.
  Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).

  These look for what attack tooling and first-stage scripts contain, not for
  one malware family. They only see files that cross a monitored link without
  encryption. Each rule bounds the file size to keep scanning cheap.
*/

rule TechDetechtives_Credential_Tool_Mimikatz_Text
{
    meta:
        description = "Command names and author marks of the credential-theft tool Mimikatz, in a program or a script that drives it"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "high"
    strings:
        $c1 = "sekurlsa::logonpasswords" ascii wide nocase
        $c2 = "sekurlsa::pth" ascii wide nocase
        $c3 = "lsadump::dcsync" ascii wide nocase
        $c4 = "lsadump::sam" ascii wide nocase
        $c5 = "lsadump::lsa" ascii wide nocase
        $c6 = "kerberos::golden" ascii wide nocase
        $c7 = "privilege::debug" ascii wide nocase
        $a1 = "gentilkiwi" ascii wide
        $a2 = "mimikatz" ascii wide nocase
    condition:
        filesize < 20MB and (2 of ($c*) or (1 of ($c*) and 1 of ($a*)))
}

rule TechDetechtives_PowerShell_Download_And_Run
{
    meta:
        description = "Script text that fetches content from a web address and runs it in the same file (a download cradle)"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "medium"
    strings:
        $get1 = "DownloadString(" ascii wide nocase
        $get2 = "DownloadData(" ascii wide nocase
        $get3 = ".DownloadFile(" ascii wide nocase
        $run1 = "Invoke-Expression" ascii wide nocase
        $run2 = "IEX(" ascii wide nocase
        $run3 = "IEX (" ascii wide nocase
        $run4 = "| IEX" ascii wide nocase
        $run5 = "|IEX" ascii wide nocase
        $run6 = "Start-Process" ascii wide nocase
        $web = /https?:\/\/[A-Za-z0-9.\-]{4,}/ ascii wide
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and 1 of ($get*) and 1 of ($run*) and $web
}

rule TechDetechtives_PowerShell_Encoded_Launcher
{
    meta:
        description = "A script, shortcut or batch file that starts PowerShell with a long encoded command"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "medium"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc = /-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+\/]{60,}={0,2}/ ascii wide nocase
    condition:
        filesize < 1MB and uint16(0) != 0x5A4D and $ps and $enc
}

rule TechDetechtives_Script_Disables_AMSI
{
    meta:
        description = "Script text that switches off the Windows Antimalware Scan Interface before running further code"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "high"
    strings:
        $field = "amsiInitFailed" ascii wide nocase
        $class = "System.Management.Automation.AmsiUtils" ascii wide nocase
        $func = "AmsiScanBuffer" ascii wide nocase
        $patch1 = "VirtualProtect" ascii wide nocase
        $patch2 = "GetProcAddress" ascii wide nocase
        $patch3 = "Marshal]::Copy" ascii wide nocase
    condition:
        // Programs are left out: PowerShell's own libraries contain these names.
        filesize < 2MB and uint16(0) != 0x5A4D and
        (($field and $class) or ($func and 2 of ($patch*)))
}

rule TechDetechtives_Webshell_Request_Driven_Execution
{
    meta:
        description = "Web script that runs whatever the caller sends in the request (PHP, ASP, ASP.NET or JSP web shell)"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "high"
    strings:
        $php1 = /(eval|assert)\s*\(\s*(stripslashes\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)\s*\[/ ascii nocase
        $php2 = /(system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ ascii nocase
        $php3 = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ ascii nocase
        $asp1 = /eval\s*\(\s*Request(\.Item)?\s*[\[(]/ ascii nocase
        $asp2 = /Execute\s*\(?\s*Request\s*\(/ ascii nocase
        $jsp1 = /Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter\s*\(/ ascii
        $jsp2 = /ProcessBuilder\s*\(\s*request\.getParameter\s*\(/ ascii
    condition:
        filesize < 1MB and any of them
}

rule TechDetechtives_Shortcut_Starts_Script_Interpreter
{
    meta:
        description = "Windows shortcut (.lnk) whose command starts a script interpreter with a web address, an encoded command or a hidden window"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "high"
    strings:
        $i1 = "powershell" ascii wide nocase
        $i2 = "mshta" ascii wide nocase
        $i3 = "wscript" ascii wide nocase
        $i4 = "cscript" ascii wide nocase
        $i5 = "rundll32" ascii wide nocase
        $i6 = "cmd.exe" ascii wide nocase
        $s1 = "http://" ascii wide nocase
        $s2 = "https://" ascii wide nocase
        $s3 = "-enc" ascii wide nocase
        $s4 = "hidden" ascii wide nocase
        $s5 = "FromBase64String" ascii wide nocase
        $s6 = "bypass" ascii wide nocase
    condition:
        // Shortcut header: size 0x4C, then the fixed shell-link class id.
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and filesize < 1MB and
        1 of ($i*) and 1 of ($s*)
}

rule TechDetechtives_Script_Runs_Command_Through_WScript_Shell
{
    meta:
        description = "HTML application or script that uses WScript.Shell to start PowerShell or cmd, the usual shape of an HTA, VBS or JS dropper"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "medium"
    strings:
        $shell = "WScript.Shell" ascii wide nocase
        $make1 = "ActiveXObject" ascii wide
        $make2 = "CreateObject" ascii wide nocase
        $hta = "<HTA:APPLICATION" ascii wide nocase
        $run1 = "powershell" ascii wide nocase
        $run2 = "cmd /c" ascii wide nocase
        $run3 = "cmd.exe /c" ascii wide nocase
        $run4 = "mshta " ascii wide nocase
        $hide1 = "-w hidden" ascii wide nocase
        $hide2 = "-windowstyle hidden" ascii wide nocase
        $hide3 = "http://" ascii wide nocase
        $hide4 = "https://" ascii wide nocase
        $hide5 = "-enc" ascii wide nocase
    condition:
        filesize < 500KB and uint16(0) != 0x5A4D and $shell and 1 of ($make*, $hta) and
        1 of ($run*) and 1 of ($hide*)
}

rule TechDetechtives_Program_Exports_ReflectiveLoader
{
    meta:
        description = "Windows program carrying a ReflectiveLoader routine, the in-memory loader used by Metasploit and Cobalt Strike payloads"
        author = "TechDetechtives"
        date = "2026-10-05"
        severity = "high"
    strings:
        $loader1 = "ReflectiveLoader" ascii
        $loader2 = "_ReflectiveLoader@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and any of them
}
