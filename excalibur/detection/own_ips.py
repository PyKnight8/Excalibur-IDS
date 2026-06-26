import socket


def discover_own_ips():
    addresses = {"127.0.0.1"}
    hostname = socket.gethostname()

    try:
        for address in socket.gethostbyname_ex(hostname)[2]:
            addresses.add(address)
    except OSError:
        pass

    for probe_host in ("8.8.8.8", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((probe_host, 80))
                addresses.add(sock.getsockname()[0])
        except OSError:
            pass

    return sorted(address for address in addresses if address)
