/*
   AetherAV core detection rules (original).
   Behavioral / content patterns that catch malware *variants* a hash never
   will. yara-x compatible. Conservative conditions to keep false positives low.
*/

rule AetherAV_EICAR_TestFile
{
    meta:
        description = "EICAR anti-malware test file"
        severity    = "test"
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $e
}

rule AetherAV_Webshell_PHP
{
    meta:
        description = "Generic PHP web shell - request-driven command execution"
        severity    = "high"
    strings:
        $php = "<?php"
        $exec1 = "system($_"
        $exec2 = "shell_exec($_"
        $exec3 = "passthru($_"
        $exec4 = "popen($_"
        $exec5 = "proc_open("
        $eval  = "eval("
        $b64   = "base64_decode("
        $assert= "assert($_"
        $in1   = "$_REQUEST["
        $in2   = "$_POST["
        $in3   = "$_GET["
        $in4   = "$_COOKIE["
    condition:
        $php and (
            any of ($exec1,$exec2,$exec3,$exec4) or
            ($eval and $b64) or
            ($exec5 and any of ($in1,$in2,$in3,$in4)) or
            ($assert and any of ($in1,$in2,$in3,$in4))
        )
}

rule AetherAV_Webshell_JSP
{
    meta:
        description = "Generic JSP web shell"
        severity    = "high"
    strings:
        $jsp = "<%"
        $rt  = "Runtime.getRuntime().exec("
        $pb  = "ProcessBuilder("
        $req = "request.getParameter("
    condition:
        $jsp and $req and ($rt or $pb)
}

rule AetherAV_PowerShell_Cradle
{
    meta:
        description = "PowerShell download-execute / encoded cradle"
        severity    = "high"
    strings:
        $ps   = "powershell" nocase
        $enc  = "-enc" nocase
        $enc2 = "-EncodedCommand" nocase
        $hidden = "-w hidden" nocase
        $nop  = "-nop" nocase
        $iex  = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
        $dl1  = "DownloadString(" nocase
        $dl2  = "DownloadFile(" nocase
        $dl3  = "Net.WebClient" nocase
        $fb64 = "FromBase64String(" nocase
    condition:
        ($iex or $iex2) and (any of ($dl1,$dl2,$dl3)) or
        ($ps and (any of ($enc,$enc2)) and (any of ($hidden,$nop))) or
        ($fb64 and ($iex or $iex2))
}

rule AetherAV_LOLBin_Download
{
    meta:
        description = "Living-off-the-land binary abused to fetch a remote payload"
        severity    = "high"
    strings:
        $c1 = "certutil -urlcache" nocase
        $c2 = "certutil  -urlcache" nocase
        $c3 = "bitsadmin /transfer" nocase
        $c4 = "regsvr32 /s /u /i:http" nocase
        $c5 = "regsvr32 /s /n /u /i:http" nocase
        $c6 = "mshta http" nocase
        $c7 = "mshta vbscript:" nocase
        $c8 = "rundll32 javascript:" nocase
        $c9 = "wmic process call create" nocase
    condition:
        any of them
}

rule AetherAV_Linux_ReverseShell
{
    meta:
        description = "Linux reverse-shell one-liners"
        severity    = "high"
    strings:
        $a = "bash -i >& /dev/tcp/"
        $b = "bash -i >&/dev/tcp/"
        $c = "/dev/tcp/"
        $d = "sh -i"
        $e = "python -c 'import socket"
        $f = "import socket,subprocess,os"
        $g = "socket.SOCK_STREAM"
        $h = "pty.spawn("
        $nc1 = "nc -e /bin/sh"
        $nc2 = "ncat -e /bin/sh"
        $nc3 = "mkfifo /tmp/"
    condition:
        $a or $b or ($c and $d) or
        ($e and $g) or ($f and $h) or
        any of ($nc1,$nc2) or ($nc3 and $c)
}

rule AetherAV_Ransom_Note
{
    meta:
        description = "Generic ransomware ransom-note language"
        severity    = "high"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "to decrypt your files" nocase
        $d = "pay the ransom" nocase
        $e = "bitcoin" nocase
        $f = "decryption key" nocase
        $g = "your documents, photos, databases" nocase
        $h = ".onion" nocase
    condition:
        (any of ($a,$b,$c,$g)) and (any of ($d,$e,$f,$h))
}

rule AetherAV_Mimikatz
{
    meta:
        description = "Mimikatz credential-dumping tool markers"
        severity    = "high"
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "sekurlsa::" nocase
        $c = "mimikatz" nocase
        $d = "gentilkiwi" nocase
        $e = "privilege::debug" nocase
        $f = "lsadump::" nocase
    condition:
        2 of them
}

rule AetherAV_CobaltStrike_Indicators
{
    meta:
        description = "Cobalt Strike beacon / artifact indicators"
        severity    = "high"
    strings:
        $a = "beacon.dll" nocase
        $b = "beacon.x64.dll" nocase
        $c = "ReflectiveLoader" nocase
        $d = "%s as %s\\%s: %d"
        $e = "powershell -nop -exec bypass -EncodedCommand" nocase
        $f = "%%IMPORT%%"
    condition:
        2 of them or $c
}

rule AetherAV_Office_Macro_Dropper
{
    meta:
        description = "Office VBA macro auto-exec + shell/download behavior"
        severity    = "high"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $auto4 = "Auto_Open" nocase
        $s1 = "Shell(" nocase
        $s2 = "WScript.Shell" nocase
        $s3 = "CreateObject(" nocase
        $s4 = "powershell" nocase
        $s5 = "MSXML2.XMLHTTP" nocase
        $s6 = "ADODB.Stream" nocase
        $s7 = "URLDownloadToFile" nocase
    condition:
        (any of ($auto1,$auto2,$auto3,$auto4)) and
        (any of ($s1,$s4,$s5,$s7) or ($s3 and any of ($s2,$s6)))
}

rule AetherAV_Script_Obfuscation
{
    meta:
        description = "Heavy script obfuscation (decode-and-eval)"
        severity    = "medium"
    strings:
        $a = "String.fromCharCode(" nocase
        $b = "eval(unescape(" nocase
        $c = "eval(atob(" nocase
        $d = "document.write(unescape(" nocase
        $e = "\\x"
        $g = "unescape(" nocase
        $eval = "eval(" nocase
    condition:
        // Scripts only: skip real executables (MZ header) - compiled apps (Tauri,
        // Node/Electron, drivers) embed JS/HTML that would otherwise match here.
        uint16(0) != 0x5A4D and (
            any of ($b,$c,$d) or
            ($a and $eval) or ($g and $eval and #e > 30)
        )
}

rule AetherAV_UPX_Packed
{
    meta:
        description = "UPX-packed executable (often used to evade hashing)"
        severity    = "info"
    strings:
        $u0 = "UPX0"
        $u1 = "UPX1"
        $u2 = "UPX!"
        $mz = { 4D 5A }
    condition:
        $mz at 0 and 2 of ($u0,$u1,$u2)
}

rule AetherAV_Suspicious_PE_Imports
{
    meta:
        description = "PE importing a process-injection / dynamic-API toolkit"
        severity    = "medium"
    strings:
        $mz = { 4D 5A }
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "SetWindowsHookEx"
        $g = "NtUnmapViewOfSection"
        $h = "QueueUserAPC"
    condition:
        // GetProcAddress / LoadLibraryA were dropped on purpose: they're in EVERY
        // normal PE, so they only inflated false positives. Match on the actual
        // injection primitives. severity = medium => engine treats this Suspicious.
        $mz at 0 and (
            ($a and $b and $c) or
            ($b and $g) or
            ($h and $a) or
            (3 of ($a,$b,$c,$d,$g,$h))
        )
}

rule AetherAV_XOR_PE_Embedded
{
    meta:
        description = "Embedded PE header (dropper carrying a payload)"
        severity    = "medium"
    strings:
        $dos = "This program cannot be run in DOS mode"
    condition:
        #dos > 1
}
