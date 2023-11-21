
import colorama
from colorama import Fore, Back, Style
import requests
import threading
import nmap
import time
from scapy.all import *
colorama.init(autoreset=True)

def print_title():
    version = "Version 1.0.0"
    title = '''
|  __ \               ___|           _)       |   
| |   |  _ \   __| \___ \   __|  __| | __ \  __|  
| |   | (   |\__ \       | (    |    | |   | |   
| ____/ \___/ ____/ _____/ \___|_|   _| .__/ \__|  
                                     _|         
    Creator : dinerbone._ 

    This is a program for ethical hacking on websites. Version 1.0.0.
    '''
    print(Back.BLACK + Fore.CYAN + title)
    print(Back.BLACK + Fore.RED + version)

def DDOS():
    print_title()

    url = input("Url --> ")
    # Sending multiple requests using threading
    def Ddos():
        requests.get(url)
    threads = []
    for _ in range(3):  # Sending three requests concurrently
        thread = threading.Thread(target=Ddos)
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
def run_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sS -p 1-2000')  # Adjust scan arguments as needed

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print(f"Host: {host} | State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"Port: {port} | State: {nm[host][proto][port]['state']}")
def threaded_scan(target):
    scan_thread = threading.Thread(target=run_nmap_scan, args=(target,))
    scan_thread.start()
    scan_thread.join()
def scan_ports(target, ports, timeout=1):
    open_ports = []
    for port in ports:
        src_port = RandShort()
        response = sr1(IP(dst=target)/TCP(sport=src_port, dport=port, flags="S"), timeout=timeout, verbose=0)
        if response and response.haslayer(TCPConnector):
            if response[TCP_CONNECTION_INFO].flags == 18:  # Check if the TCP flag is SYN-ACK (18)
                open_ports.append(port)
    return open_ports

def run_scapy_scan():
    target_ip = input("Enter the target IP address to scan: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))

    port_range = range(start_port, end_port + 1)

    open_ports = scan_ports(target_ip, port_range)
    if open_ports:
        print(f"Open ports on {target_ip}: {open_ports}")
    else:
        print(f"No open ports found on {target_ip}")


principal_title = '''
                                   _______         ___________           .__          
  _____ _____ ____________    ____ \   _  \___  __ \__    ___/___   ____ |  |   ______
 /     \\__  \\_  __ \__  \ _/ ___\/  /_\  \  \/ /   |    | /  _ \ /  _ \|  |  /  ___/
|  Y Y  \/ __ \|  | \// __ \\  \___\  \_/   \   /    |    |(  <_> |  <_> )  |__\___ \ 
|__|_|  (____  /__|  (____  /\___  >\_____  /\_/     |____| \____/ \____/|____/____  >
      \/     \/           \/     \/       \/                                       \/
Dev : Marak0v
Version 1.0.3-Open Source
'''
print(Back.BLACK + Fore.CYAN + principal_title)
menu = {
    '1': "DOS",
    '2': "Nmap",
    '4': "Credit",
    '3': "Scapy",
    '5': "Exit"  
}
while True:
    options = list(menu.keys())
    options.sort()
    for entry in options:
        print(entry, menu[entry])

    selection = input("Please Select: ")
    if selection == '1':
        DDOS()
    elif selection == '2':
        target_ip = input("Enter the target IP address or range to scan: ")
        print('If your pc is not powerfull it can take a wille so yeah')
        print('Actual Nmap command use "Nmap -sS IP -p 1-2000"')
        run_nmap_scan(target_ip)
    elif selection == '3':
        print('It like nmap but faster :]')
        run_scapy_scan()
        time.sleep(10)
    elif selection == '4':
        print('''
Code made by Makar0v
Contact me on discord dinerbone._
It's a simple Tools box made in around
2 hours with a 20-minute break, so it's not perfect,
but you can use the code in your project :)

Ps: There can be some error
It's an open-source program,
so you can check for any
rats or malware. I spent some time coding this,
so please don't assume it's a RAT because it's not. Thank you!
        ''')
        time.sleep(10)
    elif selection == '5':
        break
    else:
        print("Unknown Option Selected!")
