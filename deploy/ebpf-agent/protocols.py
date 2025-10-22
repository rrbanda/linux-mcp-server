"""
A mapping of common TCP/UDP ports to their corresponding application protocols.
"""

PORT_TO_PROTOCOL = {
    20: "FTP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP",
    389: "LDAP",
    443: "HTTPS/TLS",
    445: "SMB",
    514: "Syslog",
    636: "LDAPS",
    853: "DNS over TLS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    27017: "MongoDB",
    27018: "MongoDB",
}


def get_protocol(port):
    """
    Returns the protocol name for a given port, or 'Unknown' if not found.
    """
    return PORT_TO_PROTOCOL.get(port, "Unknown")
