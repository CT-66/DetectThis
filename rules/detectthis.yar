rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test string (harmless, used to validate the pipeline)"
        severity    = "low"
        false_pos   = "None in practice; only test files contain this string"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_Process_Injection_APIs
{
    meta:
        description = "PE referencing several classic process-injection APIs together"
        severity    = "high"
        why         = "Allocate + write + start a thread in another process is the textbook injection chain"
        false_pos   = "Debuggers, some AV/EDR agents, game anti-cheat, legit installers"
    strings:
        $a1 = "VirtualAllocEx"       ascii wide
        $a2 = "WriteProcessMemory"   ascii wide
        $a3 = "CreateRemoteThread"   ascii wide
        $a4 = "NtUnmapViewOfSection" ascii wide
        $a5 = "QueueUserAPC"         ascii wide
        $a6 = "SetThreadContext"     ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Packer_UPX_Or_Similar
{
    meta:
        description = "UPX-style packer markers (section names / banner)"
        severity    = "medium"
        why         = "Packed binaries hide imports and strings; static results become unreliable"
        false_pos   = "Legit software sometimes ships UPX-packed to reduce size"
    strings:
        $s1 = "UPX0"
        $s2 = "UPX1"
        $s3 = "UPX!"
        $s4 = "This file is packed with the UPX executable packer" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s1, $s2, $s3) or $s4)
}

rule Suspicious_Network_C2_Indicators
{
    meta:
        description = "Executable with hardcoded IPv4 URL or download/C2-style keywords plus network APIs"
        severity    = "medium"
        why         = "Malware commonly beacons to hardcoded servers and uses generic HTTP downloaders"
        false_pos   = "Updaters, telemetry agents, installers that fetch components"
    strings:
        $url_ip  = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:\/][^\s"']{0,60}/ ascii wide
        $kw1     = "/gate.php"   ascii wide nocase
        $kw2     = "/panel/"     ascii wide nocase
        $kw3     = "beacon"      ascii wide nocase
        $kw4     = "User-Agent: Mozilla/4.0 (compatible; MSIE" ascii wide
        $api1    = "InternetOpenUrl"    ascii wide
        $api2    = "URLDownloadToFile"  ascii wide
        $api3    = "WinHttpOpen"        ascii wide
    condition:
        uint16(0) == 0x5A4D and (
            ($url_ip and 1 of ($api*)) or
            (2 of ($kw*) and 1 of ($api*))
        )
}

rule Suspicious_Persistence_Run_Key
{
    meta:
        description = "Executable containing a Run-key path plus registry write API"
        severity    = "medium"
        why         = "Writing to CurrentVersion\\Run is the most common persistence trick"
        false_pos   = "Any installer or auto-updating application"
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $api = "RegSetValueEx" ascii wide
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule DetectThis_Canary_Sample
{
    meta:
        description = "Benign canary sample built for this project (ground-truth test)"
        severity    = "medium"
        why         = "Verifies the pipeline can find planted markers"
        false_pos   = "None: marker is unique to this project"
    strings:
        $marker = "DETECTTHIS_CANARY_MARKER_7f3a"
    condition:
        $marker
}
