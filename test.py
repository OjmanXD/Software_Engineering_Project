import nmap

def scan_ports(target_ip):
    scan_results = {}
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-p-')
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            scan_results[host] = {}
            for proto in nm[host].all_protocols():
                scan_results[host][proto] = []
                lport = nm[host][proto].keys()
                for port in lport:
                    port_info = nm[host][proto][port]
                    if port_info['state'] == 'open':
                        service = port_info['name']
                        scan_results[host][proto].append({"port": port, "service": service})
    return scan_results

out = scan_ports("45.33.32.156")
print(out)