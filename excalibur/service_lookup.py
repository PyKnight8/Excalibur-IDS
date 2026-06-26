DEFAULT_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    636: "LDAPS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5985: "WinRM",
    5986: "WinRM HTTPS",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def get_service_name(protocol, port):
    try:
        normalized_port = int(port)
    except (TypeError, ValueError):
        return "Unknown"
    return DEFAULT_SERVICES.get(normalized_port, "Unknown")


def service_case_sql(port_column="dst_port"):
    clauses = [
        f"WHEN {int(port)} THEN '{name.replace(chr(39), chr(39) + chr(39))}'"
        for port, name in sorted(DEFAULT_SERVICES.items())
    ]
    return f"CASE {port_column} {' '.join(clauses)} ELSE 'Unknown' END"
