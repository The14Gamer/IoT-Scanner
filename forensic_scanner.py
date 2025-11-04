import nmap
import sys
import json

def scan_iot_device(target_ip):
    """
    Scans an IoT device for open ports and services using nmap.
    """
    nm = nmap.PortScanner()
    
    print(f"[*] Starting scan on target: {target_ip}")
    
    # -sV: attempts to determine service version
    # -p 1-1000: scans ports 1 through 1000
    try:
        nm.scan(hosts=target_ip, arguments='-sV -p 1-1000')
    except nmap.nmap.PortScannerError as e:
        print(f"[!] Error during scan: {e}")
        return
        
    scan_results = {}
    
    for host in nm.all_hosts():
        scan_results[host] = {
            'status': nm[host].state(),
            'ports': {}
        }
        
        # Check if the host is up and has TCP ports
        if nm[host].state() == 'up' and 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                port_info = nm[host]['tcp'][port]
                scan_results[host]['ports'][port] = {
                    'state': port_info['state'],
                    'name': port_info.get('name', 'N/A'),
                    'product': port_info.get('product', 'N/A'),
                    'version': port_info.get('version', 'N/A')
                }
    
    return scan_results

def print_results(results):
    """
    Prints the scan results in a readable format.
    """
    if not results:
        print("[*] No scan results to display.")
        return

    for host, data in results.items():
        print(f"\nHost: {host} ({data['status']})")
        print("-------------------------------")
        
        if not data['ports']:
            print("No open ports found.")
            continue
        
        print("Open Ports:")
        for port, info in data['ports'].items():
            print(f"  Port: {port}")
            print(f"    State: {info['state']}")
            print(f"    Service: {info['name']}")
            print(f"    Product: {info['product']}")
            print(f"    Version: {info['version']}")
            print("-" * 20)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python iot_scanner.py <target_ip>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    results = scan_iot_device(target_ip)
    
    if results:
        print_results(results)
        
        # You can also save the results to a JSON file for later analysis
        output_filename = f"{target_ip}_scan_results.json"
        with open(output_filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\n[*] Results saved to {output_filename}")