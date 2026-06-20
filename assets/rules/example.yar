/*
 * Starter YARA-X rules for AetherAV.
 * Real deployments load curated rule packs (e.g. YARAhub, internal IR rules).
 */

rule EICAR_Test_File
{
    meta:
        description = "Standard AV test file (not real malware)"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
        severity    = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "PowerShell download-and-execute pattern (fileless dropper)"
        mitre       = "T1059.001"
        severity    = "high"
    strings:
        $a = "DownloadString" nocase
        $b = "IEX"            nocase
        $c = "FromBase64String" nocase
        $net = "Net.WebClient" nocase
    condition:
        $net and ($a or $c) and $b
}
