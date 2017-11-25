#https://readwrite.com/2014/04/10/raspberry-pi-vpn-tutorial-server-secure-web-browsing/
#TODO: Remove use of os.system

import hashlib
import os
import subprocess
import sys

print("This script is required to be ran as the root user.")
print("Steps you will need to take after running this script:")
print("\tConfigure your router to give this PI a static IP")
print("\tConfigure your router to forward port 1194 to this PI")
input("PRESS ENTER TO CONTINUE")


print("\n\n===INSTALLING OPENVPN===")
os.system("sudo apt-get install openvpn")

# Switch to root so that we can access our openvpn directory
os.system("rm -rf /etc/openvpn/easy-rsa/")
os.system("cp -r /usr/share/doc/openvpn/examples/easy-rsa/2.0/ /etc/openvpn/easy-rsa/")

def configureVarsFile():
    """Sets the path for the easy-rsa directory"""
    FILE_NAME = "/etc/openvpn/easy-rsa/vars"
    with open(FILE_NAME, "r") as f:
        lines = f.readlines()

    with open(FILE_NAME, "w") as f:
        for line in lines:
            if "export EASY_RSA=" in line:
                line = 'export EASY_RSA="/etc/openvpn/easy-rsa"\n'

            f.write(line)

configureVarsFile()

# We need to make a few files executable
os.system("cd /etc/openvpn/easy-rsa/ && chmod 700 whichopensslcnf pkitool clean-all")

print("\n\n===CLEANING EXISTING CONFIG AND INITIALISING SERVER===")
COMMAND_PREFIX = "cd /etc/openvpn/easy-rsa/ && source ./vars"
SERVER_NAME = input("Name your VPN server:")
def initServer(serverName):
    """Creates a bash shell that does quite a lot. We need to source our vars, clean existing keys,
    init and create our new server"""

    bashShell = subprocess.Popen(["sudo", "/bin/bash"],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE)
    bashShell.communicate(COMMAND_PREFIX.encode("utf-8") \
                          + b" && ./clean-all && ./pkitool --initca && ./pkitool --server " \
                          + serverName.encode("utf-8") + b"\n")

initServer(SERVER_NAME)

def initKeys():
    """Interactively generates the client side keys"""

    print("\n\n===GENERATING KEYS===")
    KEY_NAMES = input("Enter a space separated list of client key names:").split()
    for keyName in KEY_NAMES:
        bashShell = subprocess.Popen(["sudo", "/bin/bash"],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE)
        bashShell.communicate(COMMAND_PREFIX.encode("utf-8") \
                              + b" && ./pkitool --pass " \
                              + keyName.encode("utf-8") + b"\n")

    print("Use the same password as before for each of the following")
    for keyName in KEY_NAMES:
        os.system("cd /etc/openvpn/easy-rsa/keys && openssl rsa -in {0}.key -des3 -out {0}.3des.key".format(keyName))

initKeys()

print("\n\n===BUILDING DH AND GENERATING HMAC===")
bashShell = subprocess.Popen(["sudo", "/bin/bash"],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)
bashShell.communicate(COMMAND_PREFIX.encode("utf-8") \
                      + b" && ./build-dh && openvpn --genkey --secret keys/ta.key\n")

print("\n\n===GENERATING server.conf===")
LOCAL_IP = input("Your Pi's local IP address (something like 192.168.0.x):")
def genServerConf(serverName, localIp):
    """Writes all the config that openvpn will need"""

    with open("/etc/openvpn/server.conf", "w") as f:
        f.write("local {0} # SWAP THIS NUMBER WITH YOUR RASPBERRY PI IP ADDRESS\n".format(localIp))
        f.write("dev tun\n")
        f.write("proto udp #Some people prefer to use tcp. Don't change it if you don't know.\n")
        f.write("port 1194\n")

        f.write("ca /etc/openvpn/easy-rsa/keys/ca.crt\n")
        f.write("cert /etc/openvpn/easy-rsa/keys/{0}.crt # SWAP WITH YOUR CRT NAME\n".format(serverName))
        f.write("key /etc/openvpn/easy-rsa/keys/{0}.key # SWAP WITH YOUR KEY NAME\n".format(serverName))
        f.write("dh /etc/openvpn/easy-rsa/keys/dh1024.pem # If you changed to 2048, change that here!\n")
        f.write("server 10.8.0.0 255.255.255.0\n")

        f.write("# server and remote endpoints\n")
        f.write("ifconfig 10.8.0.1 10.8.0.2\n")

        f.write("# Add route to Client routing table for the OpenVPN Server\n")
        f.write('push "route 10.8.0.1 255.255.255.255"\n')
        f.write("# Add route to Client routing table for the OpenVPN Subnet\n")
        f.write('push "route 10.8.0.0 255.255.255.0"\n')
        f.write("# your local subnet\n")
        f.write('push "route {0} 255.255.255.0" # SWAP THE IP NUMBER WITH YOUR RASPBERRY PI IP ADDRESS\n'.format(localIp))

        f.write("# Set primary domain name server address to the SOHO Router\n")
        f.write("# If your router does not do DNS, you can use Google DNS 8.8.8.8\n")
        f.write('push "dhcp-option DNS 192.168.0.1" # This should already match your router address and not need to be changed\n')

        f.write("# Override the Client default gateway by using 0.0.0.0/1 and\n")
        f.write("# 128.0.0.0/1 rather than 0.0.0.0/0. This has the benefit of\n")
        f.write("# overriding but not wiping out the original default gateway.\n")
        f.write('push "redirect-gateway def1"\n')

        f.write("client-to-client\n")
        f.write("duplicate-cn\n")
        f.write("keepalive 10 120\n")
        f.write("tls-auth /etc/openvpn/easy-rsa/keys/ta.key 0\n")
        f.write("cipher AES-128-CBC\n")
        f.write("comp-lzo\n")
        f.write("user nobody\n")
        f.write("group nogroup\n")
        f.write("persist-key\n")
        f.write("persist-tun\n")
        f.write("status /var/log/openvpn-status.log 20\n")
        f.write("log /var/log/openvpn.log\n")
        f.write("verb 1\n")

genServerConf(SERVER_NAME, LOCAL_IP)

def updateSysCtl():
    """Updates the file /etc/sysctl.conf to set net.ipv4.ip_forward=1"""
    print("\n\n===ENABLING FORWARDING IN /etc/sysctl.conf===")

    FILE_NAME = "/etc/sysctl.conf"

    # Find the line for ipv4 forwarding and uncomment it
    with open(FILE_NAME, "r") as f:
        lines = f.readlines()

    with open(FILE_NAME, "w") as f:
        for line in lines:
            if "#net.ipv4.ip_forward=1" in line:
                line = "net.ipv4.ip_forward=1\n"

            f.write(line)

    os.system("sysctl -p")

updateSysCtl()

def addFirewallRule(localIp):
    """Creates a script that will enable the correct firewall rules"""

    print("\n\n===ADDING FIREWALL RULE===")
    print("Assuming connected over ethernet (eth0)")

    SCRIPT_NAME = "/etc/firewall-openvpn-rules.sh"

    # Create the script
    with open(SCRIPT_NAME, "w") as f:
        f.write("#!/bin/sh\n")
        f.write("iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j SNAT --to-source {0}\n".format(localIp))

    # Now we need to make sure it will be executable
    os.system("chmod 700 {0} && chown root {0}".format(SCRIPT_NAME))

    # And make sure that it always gets executed at startup
    INTERFACES_FILE = "/etc/network/interfaces"

    # First read in all the lines in the interfaces file
    with open(INTERFACES_FILE, "r") as f:
        interfacesLines = f.readlines()

    # Then write them back, but with an additional line in the startup routine
    with open(INTERFACES_FILE, "w") as f:
        foundLine = False

        INSERT_STRING = "\tpre-up /etc/firewall-openvpn-rules.sh\n"
        for line in interfacesLines:
            if foundLine and INSERT_STRING not in line:
                f.write(INSERT_STRING)

            f.write(line)

            foundLine = "iface eth0 inet dhcp" in line

addFirewallRule(LOCAL_IP)

print("\n\n===SERVER AND KEY CONFIGURATION COMPELETE, PREPARING TO GENERATING CLIENT KEY FILES===")
def prepKeyFileGeneration():
    """Writes config that will be used by another script to generate key files to be distributed to
    clients"""

    PUBLIC_IP = input("Enter your public IP address:")

    with open("/etc/openvpn/easy-rsa/keys/Default.txt", "w") as f:
        f.write("client")
        f.write("dev tun")
        f.write("proto udp")
        f.write("remote {0} 1194".format(PUBLIC_IP))
        f.write("resolv-retry infinite")
        f.write("nobind")
        f.write("persist-key")
        f.write("persist-tun")
        f.write("mute-replay-warnings")
        f.write("ns-cert-type server")
        f.write("key-direction 1")
        f.write("cipher AES-128-CBC")
        f.write("comp-lzo")
        f.write("verb 1")
        f.write("mute 20")

    # To generate our keys we need to use someone else's script from github
    print("Downloading key generation script from gist...")
    MAKEOPENVPN_PATH = "https://gist.githubusercontent.com/laurenorsini/10013430/raw/df70eae7b573aaa16c417bc54c2e0c03303501e6/MakeOpenVPN.sh"
    MAKEOPENVPN_FILENAME = "MakeOpenVPN.sh"
    os.system("cd /etc/openvpn/easy-rsa/keys && wget --cut-dirs=4 {0}".format(MAKEOPENVPN_PATH))

    # Check the hash of the downloaded file against a hash that was computed earlier to make sure
    # we're not just executing arbitrary code
    downloadedHash = hashlib.sha256()
    with open("etc/openvpn/easy-rsa/keys/{0}".format(MAKEOPENVPN_FILENAME), "rb", buffering=0) as f:
        for buffer in iter(lambda: f.read(128 * 1024), b''):
            downloadedHash.update(buffer)

    correctHash = "74378b0e65c4708285e16b98ffcecbb53fa8f107cce6bbbcac79a645a61c1893"

    # If the hash is wrong alert the user and give them the option to exit
    if correctHash is not downloadedHash.hexdigest():
        print("The downloaded key generation script does not match the expected hash.")
        print("This may mean the file has been tampered with, or simply updated.")
        print("If you are comfortable reading bash scripts, review the file at")
        print("/etc/openvpn/easy-rsa/keys/{0} to check for anything malicious.".format(MAKEOPENVPN_FILENAME))
        print("Please raise an issue on my github and I'll update the hash if necessary.")
        inputChar = input("Enter 'y' if you have verified that the file is safe and wish to continue, or any other character to exit:")

        if inputChar.lower() is not "y":
            sys.exit(1)

    os.system("cd /etc/openvpn/easy-rsa/keys && chmod 700 {0} && ./{0}".format(MAKEOPENVPN_FILENAME))

prepKeyFileGeneration()


print("\n\n===DONE!===")
