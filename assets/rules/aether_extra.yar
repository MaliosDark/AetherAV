/*
   AetherAV extra detection rules (original, authored by us).
   Expands our OWN coverage so the default install does not depend on any
   third-party rule pack. yara-x compatible. Conditions are deliberately tight
   (multiple specific indicators) to keep false positives near zero.
*/

rule AetherAV_CryptoMiner
{
    meta:
        description = "Cryptocurrency miner (XMRig / stratum) indicators"
        severity    = "high"
    strings:
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $x1 = "xmrig" nocase
        $x2 = "--donate-level" nocase
        $x3 = "cryptonight" nocase
        $x4 = "randomx" nocase
    condition:
        (any of ($pool*)) and (any of ($x*)) or 2 of ($x*)
}

rule AetherAV_Linux_Wiper
{
    meta:
        description = "Destructive disk wipe / fork-bomb"
        severity    = "high"
    strings:
        $a = "dd if=/dev/zero of=/dev/sd"
        $b = "dd if=/dev/urandom of=/dev/sd"
        $c = "mkfs." nocase
        $d = "rm -rf --no-preserve-root"
        $e = ":(){ :|:& };:"
        $f = "/dev/sda"
    condition:
        // scripts only - legit disk tools (mkfs/dd, ELF) contain these strings
        uint16be(0) != 0x4D5A and uint32be(0) != 0x7F454C46 and
        ($a or $b or $d or $e or ($c and $f))
}

rule AetherAV_Credential_Dump_Linux
{
    meta:
        description = "Linux credential theft (shadow/passwd exfiltration)"
        severity    = "high"
    strings:
        $sh1 = "cat /etc/shadow"
        $sh2 = "cp /etc/shadow"
        $sh3 = "unshadow"
        $sh4 = "/etc/shadow /etc/passwd"
        $hist = "~/.bash_history"
        $exfil1 = "curl" nocase
        $exfil2 = "wget" nocase
        $exfil3 = "nc " nocase
    condition:
        uint16be(0) != 0x4D5A and uint32be(0) != 0x7F454C46 and
        any of ($sh*) and (any of ($exfil*) or $hist)
}

rule AetherAV_Downloader_Execute_Chain
{
    meta:
        description = "Download-to-temp-then-execute dropper one-liner"
        severity    = "high"
    strings:
        $dl1 = "curl " nocase
        $dl2 = "wget " nocase
        $tmp = "/tmp/"
        $chmod = "chmod +x"
        $run1 = "&&"
        $run2 = ";"
    condition:
        uint16be(0) != 0x4D5A and uint32be(0) != 0x7F454C46 and
        (any of ($dl1, $dl2)) and $tmp and $chmod and (any of ($run1, $run2))
}

rule AetherAV_Webshell_ASPX
{
    meta:
        description = "ASP.NET web shell - request-driven process execution"
        severity    = "high"
    strings:
        $asp1 = "<%@ Page" nocase
        $asp2 = "<script runat=\"server\"" nocase
        $req  = "Request[" nocase
        $req2 = "Request.Form" nocase
        $exec1 = "Process.Start" nocase
        $exec2 = "cmd.exe" nocase
        $exec3 = "System.Diagnostics" nocase
    condition:
        (any of ($asp*)) and (any of ($req, $req2)) and (any of ($exec*))
}

rule AetherAV_Exfil_Webhook
{
    meta:
        description = "Data exfiltration to a chat webhook / bot API"
        severity    = "medium"
    strings:
        $a = "discord.com/api/webhooks/" nocase
        $b = "discordapp.com/api/webhooks/" nocase
        $c = "api.telegram.org/bot" nocase
        $tok = "token" nocase
        $send = "sendMessage" nocase
        $post = "POST" nocase
    condition:
        (any of ($a, $b, $c)) and (any of ($tok, $send, $post))
}

rule AetherAV_Token_Stealer
{
    meta:
        description = "Browser / app credential & token stealer"
        severity    = "high"
    strings:
        $a = "Local Storage\\leveldb" nocase
        $b = "Login Data" nocase
        $c = "cookies.sqlite" nocase
        $d = "key3.db"
        $e = "key4.db"
        $f = "encrypted_key" nocase
        $g = "AppData\\Roaming\\discord" nocase
    condition:
        3 of them
}

rule AetherAV_AntiSandbox
{
    meta:
        description = "Sandbox / VM / analysis-tool evasion checks"
        severity    = "medium"
    strings:
        $vm1 = "VBoxService" nocase
        $vm2 = "vboxtray" nocase
        $vm3 = "vmtoolsd" nocase
        $vm4 = "wine_get_unix_file_name"
        $dbg1 = "IsDebuggerPresent"
        $dbg2 = "CheckRemoteDebuggerPresent"
        $sb1 = "SbieDll.dll" nocase
        $sb2 = "/sys/class/dmi/id/product_name"
    condition:
        3 of them
}

rule AetherAV_Linux_Rootkit_Preload
{
    meta:
        description = "Userland LD_PRELOAD rootkit (hides files/procs by hooking libc)"
        severity    = "high"
    strings:
        $pre = "/etc/ld.so.preload"
        $h1 = "readdir"
        $h2 = "dlsym"
        $h3 = "RTLD_NEXT"
        $hide = "HIDE" nocase
    condition:
        $pre and $h3 and (any of ($h1, $h2) or $hide)
}

rule AetherAV_Reverse_Shell_Scripting
{
    meta:
        description = "Reverse/bind shell in Perl/Python/Ruby/PHP"
        severity    = "high"
    strings:
        $sock = "socket" nocase
        $perl = "Socket::INET" nocase
        $py = "socket.socket("
        $rb = "TCPSocket.open"
        $php = "fsockopen("
        $dup = "dup2"
        $exec1 = "/bin/sh"
        $exec2 = "exec(" nocase
        $spawn = "pty.spawn"
    condition:
        // scripts only - compiled interpreters/libc contain socket/dup2//bin/sh
        uint16be(0) != 0x4D5A and uint32be(0) != 0x7F454C46 and
        (any of ($perl, $py, $rb, $php) or ($sock and $dup)) and
        (any of ($exec1, $exec2) or $spawn)
}
