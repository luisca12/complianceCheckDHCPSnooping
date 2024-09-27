from netmiko import ConnectHandler
from log import authLog

import traceback
import csv
import re
import os

interface = ''
shHostname = "show run | i hostname"
shRunDevice = "show run | i dhcp|snooping|errdisable"
shIntStatus = "show interface status | exc SDW|sdw|LUM|lum|Lum"

shVlanID1101 = "show vlan id 1101"
shVlanID1103 = "show vlan id 1103"

snoopGlobalConfig = [
    'ip dhcp snooping vlan 2-3999',
    'no ip dhcp snooping information option',
    'ip dhcp snooping',
    'errdisable recovery cause dhcp-rate-limit',
    # 'errdisable recovery interval 300', # REMOVED due to not be shown on the show run, default value is 300
    'class-map match-any system-cpp-police-protocol-snooping',
    'description Protocol snooping',
    'class-map match-any system-cpp-police-dhcp-snooping',
    'description DHCP snooping'
]

snoopIntConfig = "ip dhcp snooping trust"

snoopGenIntConfig = "ip dhcp snooping limit rate 50"

# Regex Patterns
intPatt = r'[a-zA-Z]+\d+\/(?:\d+\/)*\d+'
intPatt2 = r'[Te]+\d+\/(?:1+\/)+\d+'

def complCheck(validIPs, username, netDevice):
    # This function is to check compliance configuration on the device

    for validDeviceIP in validIPs:
        missingConfig1 = False
        deviceConfigured = False
        try:
            validDeviceIP = validDeviceIP.strip()
            currentNetDevice = {
                'device_type': 'cisco_xe',
                'ip': validDeviceIP,
                'username': username,
                'password': netDevice['password'],
                'secret': netDevice['secret'],
                'global_delay_factor': 2.0,
                'timeout': 120,
                'session_log': 'netmikoLog.txt',
                'verbose': True,
                'session_log_file_mode': 'append'
            }

            print(f"Connecting to device {validDeviceIP}...")
            with ConnectHandler(**currentNetDevice) as sshAccess:
                try:
                    sshAccess.enable()
                    shHostnameOut = sshAccess.send_command(shHostname)
                    authLog.info(f"User {username} successfully found the hostname {shHostnameOut}")
                    shHostnameOut = shHostnameOut.split(' ')[1]
                    shHostnameOut = shHostnameOut + "#"

                    print(f"INFO: Taking a \"{shVlanID1101}\" for device: {validDeviceIP}")
                    shVlanID1101Out = sshAccess.send_command(shVlanID1101)
                    authLog.info(f"Automation successfully ran the command:{shVlanID1101}\n{shHostnameOut}{shVlanID1101}\n{shVlanID1101Out}")

                    if "not found" in shVlanID1101Out:
                        print(f"INFO: Device {validDeviceIP} does not have VLANS 1101 and 1103, skipping device...")
                        authLog.info(f"Device {validDeviceIP} does not have VLANS 1101 and 1103, skipping device...")
                        continue

                    shVlanID1101Out1 = re.findall(intPatt, shVlanID1101Out)
                    authLog.info(f"The following interfaces were found under the command: {shVlanID1101}: {shVlanID1101Out1}")

                    print(f"INFO: Taking a \"{shVlanID1103}\" for device: {validDeviceIP}")
                    shVlanID1103Out = sshAccess.send_command(shVlanID1103)
                    authLog.info(f"Automation successfully ran the command:{shVlanID1103}\n{shHostnameOut}{shVlanID1103}\n{shVlanID1103Out}")
                    shVlanID1103Out1 = re.findall(intPatt, shVlanID1103Out)
                    authLog.info(f"The following interfaces were found under the command: {shVlanID1103}: {shVlanID1103Out1}")

                    if shVlanID1101Out1:
                        for interface in shVlanID1101Out1:
                            interface = interface.strip()
                            print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                            authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}")
                            interfaceOut = sshAccess.send_command(f'show run int {interface}')
                            if snoopIntConfig in interfaceOut:
                                print(f"INFO: Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                missingConfig1 = False
                            else:
                                print(f"INFO: Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Skipping device {validDeviceIP}")
                                missingConfig1 = True
                                break
                        if missingConfig1 == True:
                            with open('missingDHCP_Configuration.csv', mode='a', newline='') as file:
                                    writer = csv.writer(file)
                                    writer.writerow([validDeviceIP])
                            continue
                    else:
                        print(f"INFO: No interfaces found under {shVlanID1101}")
                        authLog.info(f"No interfaces found under {shVlanID1101}")
                    
                    if shVlanID1103Out1:
                        for interface in shVlanID1103Out1:
                            interface = interface.strip()
                            print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                            authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}")
                            interfaceOut = sshAccess.send_command(f'show run int {interface}')
                            if snoopIntConfig in interfaceOut:
                                print(f"INFO: Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                missingConfig1 = False
                            else:
                                print(f"INFO: Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Skipping device {validDeviceIP}")
                                missingConfig1 = True
                                break
                        if missingConfig1 == True:
                            with open('missingDHCP_Configuration.csv', mode='a', newline='') as file:
                                    writer = csv.writer(file)
                                    writer.writerow([validDeviceIP])
                            continue
                    else:
                        print(f"INFO: No interfaces found under {shVlanID1103}")
                        authLog.info(f"No interfaces found under {shVlanID1103}")

                    print(f"INFO: Taking a \"{shRunDevice}\" for device: {validDeviceIP}")
                    shRunDeviceOut = sshAccess.send_command(shRunDevice)
                    authLog.info(f"Automation successfully ran the command:{shRunDevice}\n{shHostnameOut}{shRunDevice}\n{shRunDeviceOut}")

                    for index, item in enumerate(snoopGlobalConfig):
                        if not item in shRunDeviceOut:
                            authLog.info(f"Configuration: {item} is missing from device {validDeviceIP}")
                            authLog.info(f"Skipping device {validDeviceIP}")
                            missingConfig1 = True
                            break
                        else:
                            authLog.info(f"Configuration: {item} was found on device {validDeviceIP}")
                            missingConfig1 = False
                    if missingConfig1 == True:
                        with open('missingDHCP_Configuration.csv', mode='a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([validDeviceIP])
                        continue

                    shIntStatusOut = sshAccess.send_command(shIntStatus)
                    authLog.info(f"Automation ran the command \"{shIntStatus}\" on device {validDeviceIP}\n{shHostnameOut}{shIntStatusOut}")
                    print(f"INFO: Running the following command: \"{shIntStatus}\" on device {validDeviceIP}\n{shHostnameOut}{shIntStatusOut}")
                    shIntStatusOut1 = re.findall(intPatt, shIntStatusOut)
                    authLog.info(f"Automation found the following interfaces on device {validDeviceIP}: {shIntStatusOut1}")
                    shIntStatusOut2 = [match for match in shIntStatusOut1 if not re.match(intPatt2, match)]
                    authLog.info(f"Automation filtered the following interfaces on device {validDeviceIP}, the following interfaces will be modified: {shIntStatusOut2}")
                    print(f"INFO: The following interfaces will be modified: {shIntStatusOut2}")

                    if shIntStatusOut2:
                        for interface in shIntStatusOut2:
                            interfaceOut = sshAccess.send_command(f'show run int {interface}')
                            if snoopGenIntConfig not in interfaceOut:
                                authLog.info(f"Configuration: {snoopGenIntConfig} is missing from device: {validDeviceIP} on interface {interface}")
                                authLog.info(f"Skipping device {validDeviceIP}")
                                missingConfig1 = True
                                break
                            else:    
                                print(f"INFO: Interface {interface} has configured {snoopGenIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} has configured {snoopGenIntConfig} on device {validDeviceIP}")
                                missingConfig1 = False
                                deviceConfigured = True
                    
                    if missingConfig1 == True:
                        with open('missingDHCP_Configuration.csv', mode='a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([validDeviceIP])
                        continue

                    if deviceConfigured == True:
                        with open('configuredDevices_DHCPSnooping.csv', mode='a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([validDeviceIP])
                    
                    print(f"Outputs and files successfully created for device {validDeviceIP}.\n")
                    print("For any erros or logs please check Logs -> authLog.txt\n")
                    print(f"Program finished, all the configuration has been applied.")

                except Exception as error:
                    print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
                    authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
                    authLog.error(traceback.format_exc(),"\n")
                    os.system("PAUSE")
       
        except Exception as error:
            print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
            authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
            authLog.error(traceback.format_exc(),"\n")
            with open(f"failedDevices.txt","a") as failedDevices:
                failedDevices.write(f"User {username} connected to {validDeviceIP} got an error.\n")