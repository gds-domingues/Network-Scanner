import scapy.all as scapy
import argparse
import json

def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("target", help="Target IP address or range (CIDR notation)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (default: 1-1024)")
    parser.add_argument("-o", "--output", choices=["json", "csv"], help="Output format (json/csv)")
    return parser.parse_args()

def scan_port(ip, port):
    try:
        print(f"Scanning port {port} on {ip}")
        src_port = 12345  # You can change this source port if needed
        response = scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=False)
        print(f"Response: {response}")  # Debugging: Print the response
        if response and response.haslayer(scapy.TCP):
            print(f"Port {port} is open on {ip}")
            return port, True
        else:
            print(f"Port {port} is closed on {ip}")
            return port, False
    except Exception as e:
        print(f"Error scanning port {port} on {ip}: {e}")
        return port, False

def scan_host(ip, ports):
    print(f"Scanning ports on host {ip}")
    open_ports = []
    for port in range(ports[0], ports[1] + 1):
        result = scan_port(ip, port)
        if result[1]:
            open_ports.append(result[0])
    print(f"Open ports on host {ip}: {open_ports}")
    return {ip: open_ports}

def scan_network(target, ports_range):
    interface = "Ethernet"
    print("Scanning network...")
    hosts = scapy.ARP(pdst=target)
    answered_list = scapy.srp(hosts, timeout=60, iface=interface, verbose=False)[0]
    print("ARP responses:", answered_list)  # Debugging: Print the list of ARP responses

    scan_results = {}
    for element in answered_list:
        ip = element[1].psrc
        try:
            scan_results.update(scan_host(ip, ports_range))
        except Exception as e:
            print(f"Error scanning {ip}: {e}")

    print("Scan completed.")
    return scan_results

def main():
    args = get_arguments()
    target = args.target
    ports_range = list(map(int, args.ports.split("-")))

    print(f"Scanning target: {target}")
    print(f"Scanning ports: {ports_range[0]}-{ports_range[1]}")
    print(f"Output format: {args.output}")

    scan_results = scan_network(target, ports_range)
    print("Scan results:", scan_results)  # Debugging: Print the scan results

    if args.output == "json":
        with open("scan_results.json", "w") as file:
            json.dump(scan_results, file, indent=4)
        print("Results saved to 'scan_results.json'")
    elif args.output == "csv":
        with open("scan_results.csv", "w") as file:
            for ip, ports in scan_results.items():
                file.write(f"{ip},{','.join(map(str, ports))}\n")
        print("Results saved to 'scan_results.csv'")
    else:
        for ip, ports in scan_results.items():
            print(f"IP: {ip}\tOpen Ports: {', '.join(map(str, ports))}")

if __name__ == "__main__":
    main()
