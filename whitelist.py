import ipaddress

# 與 D:\claude\blacklist\ipip.py 的 WHITELIST 保持同步，若異動請兩邊一起更新
WHITELIST = [
    '8.8.8.8/32',
    '8.8.4.4/32',
    '168.95.1.1/32',
    '168.95.192.1/32',
    '192.168.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '203.68.94.0/24',
    '203.68.95.0/24',
    '203.68.96.0/24',
    '203.68.97.0/24',
    '203.68.98.0/24',
    '203.68.99.0/24',
    '118.163.81.61',
    '118.163.81.63',
    '211.22.103.158',
    '118.163.81.62',
    '211.22.103.157',
    '129.6.15.28',
    '129.6.15.29',
    '192.5.41.40',
    '192.5.41.41',
    '203.64.247.100',
]


def build_whitelist(entries):
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            pass
    return networks


def is_whitelisted(ip_obj, whitelist_networks):
    return any(ip_obj in network for network in whitelist_networks)


def get_ip_obj(val):
    try:
        return ipaddress.ip_address(val.strip())
    except ValueError:
        return None
