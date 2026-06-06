rule ShellShock {
    meta:
        description = "ShellShock bash exploit (CVE-2014-6271)"
        severity = "critical"
        mitre = "T1190"
    strings:
        $a = "() { :; };" ascii
        $b = "() { :;};" ascii
    condition:
        any of them
}

rule Log4Shell {
    meta:
        description = "Log4Shell JNDI injection (CVE-2021-44228)"
        severity = "critical"
        mitre = "T1190"
    strings:
        $a = "${jndi:" ascii nocase
        $b = "${${lower:j}ndi:" ascii nocase
        $c = "${${::-j}${::-n}${::-d}${::-i}:" ascii nocase
    condition:
        any of them
}

rule SQLInjection {
    meta:
        description = "SQL Injection attempt in HTTP"
        severity = "high"
        mitre = "T1190"
    strings:
        $a = "' OR '1'='1" ascii nocase
        $b = "' OR 1=1--" ascii nocase
        $c = "UNION SELECT" ascii nocase
        $d = "UNION ALL SELECT" ascii nocase
        $e = "'; DROP TABLE" ascii nocase
        $f = "1=1--" ascii
        $g = "1' OR '1'='1" ascii
    condition:
        any of them
}

rule XSS {
    meta:
        description = "Cross-Site Scripting (XSS) attempt"
        severity = "medium"
        mitre = "T1059.007"
    strings:
        $a = "<script>" ascii nocase
        $b = "javascript:" ascii nocase
        $c = "onerror=" ascii nocase
        $d = "onload=" ascii nocase
        $e = "eval(" ascii nocase
        $f = "document.cookie" ascii nocase
    condition:
        2 of them
}

rule C2_Beacon_HTTP {
    meta:
        description = "Possible C2 beacon over HTTP (Cobalt Strike / Metasploit patterns)"
        severity = "high"
        mitre = "T1071.001"
    strings:
        $cs1 = "MZRE" ascii
        $cs2 = "/submit.php" ascii
        $msf1 = "Meterpreter" ascii nocase
        $msf2 = "/multi/handler" ascii
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" ascii
        $ua2 = "User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit" ascii
    condition:
        any of them
}

rule Mirai_Bot {
    meta:
        description = "Mirai botnet payload signature"
        severity = "critical"
        mitre = "T1498"
    strings:
        $a = "/bin/busybox" ascii
        $b = "MIRAI" ascii
        $c = "/bin/sh" ascii
        $d = "tftp -g" ascii
    condition:
        2 of them
}

rule HTTPScan {
    meta:
        description = "HTTP directory/vulnerability scanning"
        severity = "medium"
        mitre = "T1595.002"
    strings:
        $a = "/.git/" ascii
        $b = "/wp-admin/" ascii
        $c = "/phpmyadmin/" ascii
        $d = "/admin.php" ascii
        $e = "/.env" ascii
        $f = "/etc/passwd" ascii
        $g = "../../../etc/passwd" ascii
        $h = "/cgi-bin/" ascii
    condition:
        2 of them
}

rule PathTraversal {
    meta:
        description = "Path traversal / directory traversal attempt"
        severity = "high"
        mitre = "T1083"
    strings:
        $a = "../../../" ascii
        $b = "..%2F..%2F" ascii nocase
        $c = "%2e%2e%2f" ascii nocase
        $d = "..%5c..%5c" ascii nocase
        $e = "....//..../" ascii
    condition:
        any of them
}

rule ReverseShell {
    meta:
        description = "Reverse shell command patterns"
        severity = "critical"
        mitre = "T1059"
    strings:
        $a = "bash -i >& /dev/tcp/" ascii
        $b = "nc -e /bin/sh" ascii
        $c = "nc -e /bin/bash" ascii
        $d = "python -c 'import socket,subprocess" ascii
        $e = "perl -e 'use Socket;" ascii
        $f = "ncat -e /bin/bash" ascii
    condition:
        any of them
}

rule CredentialDump {
    meta:
        description = "Credential harvesting / password dump patterns"
        severity = "high"
        mitre = "T1552"
    strings:
        $a = "Authorization: Basic" ascii
        $b = "password=" ascii nocase
        $c = "passwd=" ascii nocase
        $d = "pwd=" ascii nocase
        $e = "secret=" ascii nocase
        $f = "api_key=" ascii nocase
        $g = "token=" ascii nocase
    condition:
        2 of them
}
