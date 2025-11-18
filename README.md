Installation
```
git clone https://github.com/The14Gamer/IoT-Scanner.git
cd IoT-Scanner
chmod +x forensic_Scanner.py 
python3 forensic_Scanner.py tryhackme.com
```
----------------------------------------------------------------------
How to Run the Script
Open your command prompt or terminal.

Navigate to the directory where you saved the iot_scanner.py file.

Execute the script by providing the IP address of your target IoT device as a command-line argument.

--------Bash--------------------------
python iot_scanner.py 192.168.1.105


--------------------------------------------------------------------
Purpose:

This tool is useful for:

    Security auditing of IoT devices

    Forensic analysis to understand what services a device is running

    Vulnerability assessment by identifying potentially vulnerable services

    Network documentation of IoT device configurations

The scanner helps security professionals and forensic investigators understand the attack surface of IoT devices by revealing what network services are exposed and what software versions are running.

-----------------------------------------------------------------------
Key Features:

    Port Scanning: Scans ports 1-1000 on the target IP address

    Service Detection: Attempts to identify what services are running and their versions (-sV flag)

    Results Display: Shows open ports, service names, products, and versions in a readable format

    Data Export: Automatically saves scan results to a JSON file for later analysis
