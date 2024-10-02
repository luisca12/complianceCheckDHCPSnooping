from netmiko import ConnectHandler
from log import authLog
from functions import failedDevices, logInCSV

import traceback
import csv
import re
import os

interface = ''
shHostname = "show run | i hostname"
shRunDevice = "show run | i dhcp|snooping|errdisable"
shIntStatus = "show interface status | exc SDW|sdw|LUM|lum|Lum"
shRunLimitRate = "show run | inc ip dhcp snooping limit rate"
shRunIntTrust = "show run | inc ip dhcp snooping trust"

shVlanID1101 = "show vlan id 1101"
shVlanID1103 = "show vlan id 1103"
shVlanID1105 = "show vlan id 1105"
shVlanID1107 = "show vlan id 1107"

snoopIntConfig = "ip dhcp snooping trust"

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

# Regex Patterns
intPatt = r'[a-zA-Z]+\d+\/(?:\d+\/)*\d+'
intPatt2 = r'[Te]+\d+\/(?:1+\/)+\d+'
shLimitRate = re.compile(r'(ip dhcp snooping limit rate)')
shIntTrust = re.compile(r'(ip dhcp snooping trust)')

def complCheckCaremore(validIPs, username, netDevice):
    # This function is to check compliance configuration on the device

    for validDeviceIP in validIPs:
        missingConfig1 = False
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

            print(f"INFO: Connecting to device {validDeviceIP}...")
            authLog.info(f"Connecting to device {validDeviceIP}")
            with ConnectHandler(**currentNetDevice) as sshAccess:
                try:
                    authLog.info(f"Connected to device: {validDeviceIP}")
                    sshAccess.enable()
                    shHostnameOut = sshAccess.send_command(shHostname)
                    authLog.info(f"User {username} successfully found the hostname {shHostnameOut} for device: {validDeviceIP}")
                    shHostnameOut = shHostnameOut.split(' ')[1]
                    shHostnameOut = shHostnameOut + "#"

                    print(f"INFO: Taking a \"{shVlanID1101}\" for device: {validDeviceIP}")
                    shVlanID1101Out = sshAccess.send_command(shVlanID1101)
                    authLog.info(f"Automation successfully ran the command:{shVlanID1101}\n{shHostnameOut}{shVlanID1101}\n{shVlanID1101Out}")
                    shVlanID1101Out1 = re.findall(intPatt, shVlanID1101Out)
                    authLog.info(f"The following interfaces were found under the command: {shVlanID1101}: {shVlanID1101Out1}, for device: {validDeviceIP}")

                    if shVlanID1101Out1 == []:
                        print(f"{shVlanID1101Out}\n\nFiltered interfaces:{shVlanID1101Out1}")
                        print(f"INFO: No interfaces found under {shVlanID1101}")
                        authLog.info(f"No interfaces found under {shVlanID1101}")
                        print(f"INFO: Device {validDeviceIP} does not have VLANS 1101 and 1103, skipping device...")
                        authLog.info(f"Device {validDeviceIP} does not have VLANS 1101 and 1103, skipping device...")
                        continue
                    else:
                        for interface in shVlanID1101Out1:
                            interface = interface.strip()
                            print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                            authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}")
                            interfaceOut = sshAccess.send_command(f'show run int {interface}')
                            authLog.info(f"{shHostnameOut}{shVlanID1101}\n{interfaceOut}")
                            if snoopIntConfig in interfaceOut:
                                print(f"INFO: Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                missingConfig1 = False
                            else:
                                print(f"INFO: Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Skipping device {validDeviceIP}")
                                print(f"INFO: Skipping device {validDeviceIP}")
                                print(f"INFO: Skipping device {validDeviceIP}")
                                missingConfig1 = True
                                break
                        if missingConfig1 == True:
                            logInCSV(validDeviceIP,filename="Devices missing DHCP Snooping Configuration")
                            continue
                    
                    print(f"INFO: Taking a \"{shVlanID1103}\" for device: {validDeviceIP}")
                    shVlanID1103Out = sshAccess.send_command(shVlanID1103)
                    authLog.info(f"Automation successfully ran the command:{shVlanID1103}\n{shHostnameOut}{shVlanID1103}\n{shVlanID1103Out}")
                    shVlanID1103Out1 = re.findall(intPatt, shVlanID1103Out)
                    authLog.info(f"The following interfaces were found under the command: {shVlanID1103}: {shVlanID1103Out1}")
                    
                    if shVlanID1103Out1 == []:
                        print(f"{shVlanID1103Out}\n\nFiltered interfaces:{shVlanID1103Out1}")
                        print(f"INFO: No interfaces found under {shVlanID1103}")
                        authLog.info(f"No interfaces found under {shVlanID1103}")
                        print(f"INFO: Device {validDeviceIP} does not have VLANS 1101 and 1103, skipping device...")
                        authLog.info(f"Device {validDeviceIP} does not have VLANS 1101 and 1103, skipping device...")
                        continue
                    else:   
                        for interface in shVlanID1103Out1:
                            interface = interface.strip()
                            print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                            authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}")
                            interfaceOut = sshAccess.send_command(f'show run int {interface}')
                            authLog.info(f"{shHostnameOut}{shVlanID1103}\n{interfaceOut}")
                            if snoopIntConfig in interfaceOut:
                                print(f"INFO: Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                missingConfig1 = False
                            else:
                                print(f"INFO: Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Skipping device {validDeviceIP}")
                                print(f"INFO: Skipping device {validDeviceIP}")
                                missingConfig1 = True
                                break
                        if missingConfig1 == True:
                            logInCSV(validDeviceIP,filename="Devices missing DHCP Snooping Configuration")   
                            continue

                    print(f"INFO: Taking a \"{shRunDevice}\" for device: {validDeviceIP}")
                    shRunDeviceOut = sshAccess.send_command(shRunDevice)
                    authLog.info(f"Automation successfully ran the command:{shRunDevice}\n{shHostnameOut}{shRunDevice}\n{shRunDeviceOut}")

                    for index, item in enumerate(snoopGlobalConfig):
                        if not item in shRunDeviceOut:
                            authLog.info(f"Configuration: {item} is missing from device {validDeviceIP}")
                            authLog.info(f"Skipping device {validDeviceIP}")
                            print(f"INFO: Skipping device {validDeviceIP}")
                            missingConfig1 = True
                            break
                        else:
                            authLog.info(f"Configuration: {item} was found on device {validDeviceIP}")
                            missingConfig1 = False
                    if missingConfig1 == True:
                        logInCSV(validDeviceIP,filename="Devices missing DHCP Snooping Configuration")
                        continue

                    print(f"INFO: Taking a \"{shRunLimitRate}\" for device: {validDeviceIP}")
                    shRunLimitRateOut = sshAccess.send_command(shRunLimitRate)
                    authLog.info(f"Automation successfully ran the command:{shRunLimitRate}\n{shHostnameOut}{shRunLimitRate}\n{shRunLimitRateOut}")

                    shRunLimitRateOut1 = shLimitRate.findall(shRunLimitRateOut)
                    authLog.info(f"Found a total of {len(shRunLimitRateOut1)} matches of {shLimitRate.pattern}")

                    if len(shRunLimitRateOut1) > 2:
                        if "ip dhcp snooping limit rate 15" in shRunLimitRateOut1:
                            logInCSV(validDeviceIP, filename="Devices missing DHCP Snooping Configuration")
                            authLog.info(f"Skipping device: {validDeviceIP} due to missconfigured dhcp snooping rate limit, rate limit 15 was found")
                            print(f"INFO: Skipping device: {validDeviceIP} due to missconfigured dhcp snooping rate limit, rate limit 15 was found")
                            continue
                        else:
                            logInCSV(validDeviceIP, filename="Totally Configured DCHP Snooping Devices")
                            authLog.info(f"Device: {validDeviceIP}, totally configured with DHCP Snooping")
                            print(f"INFO: Device: {validDeviceIP}, totally configured with DHCP Snooping")
                    else:
                        logInCSV(validDeviceIP, filename="Devices missing DHCP Snooping Configuration")
                        authLog.info(f"Skipping device: {validDeviceIP} due to less than 2 interfaces configured with ip dhcp snooping limit rate")
                        print(f"INFO: Skipping device: {validDeviceIP} due to less than 2 interfaces configured with ip dhcp snooping limit rate")
                        continue

                    print(f"Outputs and files successfully created for device {validDeviceIP}.\n")
                    print("For any erros or logs please check Logs -> authLog.txt\n")
                    print(f"Program finished, all the configuration has been applied.")

                except Exception as error:
                    print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
                    authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
                    authLog.error(traceback.format_exc(),"\n")
                    failedDevices(username,validDeviceIP,error)
                    
        except Exception as error:
            print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
            authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
            authLog.error(traceback.format_exc(),"\n")
            failedDevices(username,validDeviceIP,error)     

def complCheckElevance(validIPs, username, netDevice):
    # This function is to check compliance configuration on the device

    for validDeviceIP in validIPs:
        missingConfig1 = False
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
                'session_log': 'Outputs/netmikoLog.txt',
                'verbose': True,
                'session_log_file_mode': 'append'
            }

            print(f"INFO: Connecting to device {validDeviceIP}...")
            authLog.info(f"Connecting to device {validDeviceIP}")
            with ConnectHandler(**currentNetDevice) as sshAccess:
                try:
                    authLog.info(f"Connected to device: {validDeviceIP}")
                    sshAccess.enable()
                    shHostnameOut = sshAccess.send_command(shHostname)
                    authLog.info(f"User {username} successfully found the hostname {shHostnameOut} for device: {validDeviceIP}")
                    shHostnameOut = shHostnameOut.split(' ')[1]
                    shHostnameOut = shHostnameOut + "#"

                    print(f"INFO: Taking a \"{shVlanID1101}\" for device: {validDeviceIP}")
                    shVlanID1101Out = sshAccess.send_command(shVlanID1101)
                    authLog.info(f"Automation successfully ran the command:{shVlanID1101}\n{shHostnameOut}{shVlanID1101}\n{shVlanID1101Out}")
                    shVlanID1101Out1 = re.findall(intPatt, shVlanID1101Out)
                    authLog.info(f"The following interfaces were found under the command: {shVlanID1101}: {shVlanID1101Out1}, for device: {validDeviceIP}")

                    if shVlanID1101Out1 == [] or "not found" in shVlanID1101Out:
                        authLog.info(f"Device: {validDeviceIP} is an Elevance site")
                        print(f"INFO: Taking a \"{shVlanID1105}\" for device: {validDeviceIP}")
                        shVlanID1105Out = sshAccess.send_command(shVlanID1105)
                        authLog.info(f"Automation successfully ran the command:{shVlanID1105}\n{shHostnameOut}{shVlanID1105}\n{shVlanID1105Out}")
                        shVlanID1105Out1 = re.findall(intPatt, shVlanID1105Out)
                        authLog.info(f"The following interfaces were found under the command: {shVlanID1105}: {shVlanID1105Out1}, for device: {validDeviceIP}")

                        for interface in shVlanID1105Out1:
                            interface = interface.strip()
                            print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                            authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}")
                            interfaceOut = sshAccess.send_command(f'show run int {interface}')
                            authLog.info(f"{shHostnameOut}{shVlanID1105}\n{interfaceOut}")
                            if snoopIntConfig in interfaceOut:
                                print(f"INFO: Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                                missingConfig1 = False
                            else:
                                print(f"INFO: Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                                authLog.info(f"Skipping device {validDeviceIP}")
                                print(f"INFO: Skipping device {validDeviceIP}")
                                missingConfig1 = True
                                break
                        if missingConfig1 == True:
                            logInCSV(validDeviceIP,filename="Devices missing DHCP Snooping Configuration")
                            continue
                    else:
                        print(f"{shVlanID1101Out}\n\nFiltered interfaces:{shVlanID1101Out1}")
                        print(f"INFO: No interfaces found under {shVlanID1101}")
                        authLog.info(f"No interfaces found under {shVlanID1101}")
                        print(f"INFO: Device {validDeviceIP} is a Caremore site, skipping device...")
                        authLog.info(f"Device {validDeviceIP} is a Caremore site, skipping device...")
                        continue
                    
                    print(f"INFO: Taking a \"{shVlanID1107}\" for device: {validDeviceIP}")
                    shVlanID1107Out = sshAccess.send_command(shVlanID1107)
                    authLog.info(f"Automation successfully ran the command:{shVlanID1107}\n{shHostnameOut}{shVlanID1107}\n{shVlanID1107Out}")
                    shVlanID1107Out1 = re.findall(intPatt, shVlanID1107Out)
                    authLog.info(f"The following interfaces were found under the command: {shVlanID1107}: {shVlanID1107Out1}")
                     
                    for interface in shVlanID1107Out1:
                        interface = interface.strip()
                        print(f"INFO: Checking configuration for interface {interface} on device {validDeviceIP}")
                        authLog.info(f"Checking configuration for interface {interface} on device {validDeviceIP}")
                        interfaceOut = sshAccess.send_command(f'show run int {interface}')
                        authLog.info(f"{shHostnameOut}{shVlanID1107}\n{interfaceOut}")
                        if snoopIntConfig in interfaceOut:
                            print(f"INFO: Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                            authLog.info(f"Interface {interface} has configured {snoopIntConfig} on device {validDeviceIP}")
                            missingConfig1 = False
                        else:
                            print(f"INFO: Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                            authLog.info(f"Interface {interface} does NOT have configured {snoopIntConfig} on device {validDeviceIP}")
                            authLog.info(f"Skipping device {validDeviceIP}")
                            print(f"INFO: Skipping device {validDeviceIP}")
                            missingConfig1 = True
                            break
                    if missingConfig1 == True:
                        logInCSV(validDeviceIP,filename="Devices missing DHCP Snooping Configuration")   
                        continue

                    print(f"INFO: Taking a \"{shRunDevice}\" for device: {validDeviceIP}")
                    shRunDeviceOut = sshAccess.send_command(shRunDevice)
                    authLog.info(f"Automation successfully ran the command:{shRunDevice}\n{shHostnameOut}{shRunDevice}\n{shRunDeviceOut}")

                    for index, item in enumerate(snoopGlobalConfig):
                        if not item in shRunDeviceOut:
                            authLog.info(f"Configuration: {item} is missing from device {validDeviceIP}")
                            authLog.info(f"Skipping device {validDeviceIP}")
                            print(f"INFO: Skipping device {validDeviceIP}")
                            missingConfig1 = True
                            break
                        else:
                            authLog.info(f"Configuration: {item} was found on device {validDeviceIP}")
                            missingConfig1 = False
                    
                    if missingConfig1 == True:
                        logInCSV(validDeviceIP,filename="Devices missing DHCP Snooping Configuration")
                        continue

                 
                    print(f"INFO: Taking a \"{shRunIntTrust}\" for device: {validDeviceIP}")
                    shRunIntTrustOut = sshAccess.send_command(shRunIntTrust)
                    authLog.info(f"Automation successfully ran the command:{shRunIntTrust}\n{shHostnameOut}{shRunIntTrust}\n{shRunIntTrustOut}")

                    shRunLimitRateOut2 = shIntTrust.findall(shRunIntTrustOut)
                    authLog.info(f"Found a total of {len(shRunLimitRateOut2)} matches of {shIntTrust.pattern}: {shRunLimitRateOut2}")

                    if len(shRunLimitRateOut2) >= 1:
                        authLog.info(f"DHCP Snooping trust is configured on 1 or more interface.")
                    else:
                        logInCSV(validDeviceIP, filename="Devices missing DHCP Snooping Configuration")
                        authLog.info(f"Skipping device: {validDeviceIP} due to missing dhcp snooping trust command")
                        print(f"INFO: Skipping device: {validDeviceIP} due to missing dhcp snooping trust command")
                        continue

                    print(f"INFO: Taking a \"{shRunLimitRate}\" for device: {validDeviceIP}")
                    shRunLimitRateOut = sshAccess.send_command(shRunLimitRate)
                    authLog.info(f"Automation successfully ran the command:{shRunLimitRate}\n{shHostnameOut}{shRunLimitRate}\n{shRunLimitRateOut}")

                    shRunLimitRateOut1 = shLimitRate.findall(shRunLimitRateOut)
                    authLog.info(f"Found a total of {len(shRunLimitRateOut1)} matches of {shLimitRate.pattern}: {shRunLimitRateOut1}")

                    if len(shRunLimitRateOut1) > 2:
                        if "ip dhcp snooping limit rate 15" in shRunLimitRateOut1:
                            logInCSV(validDeviceIP, filename="Devices missing DHCP Snooping Configuration")
                            authLog.info(f"Skipping device: {validDeviceIP} due to missconfigured dhcp snooping rate limit, rate limit 15 was found")
                            print(f"INFO: Skipping device: {validDeviceIP} due to missconfigured dhcp snooping rate limit, rate limit 15 was found")
                            continue
                        else:
                            logInCSV(validDeviceIP, filename="Totally Configured DCHP Snooping Devices")
                            authLog.info(f"Device: {validDeviceIP}, totally configured with DHCP Snooping")
                            print(f"INFO: Device: {validDeviceIP}, totally configured with DHCP Snooping")
                    else:
                        logInCSV(validDeviceIP, filename="Devices missing DHCP Snooping Configuration")
                        authLog.info(f"Skipping device: {validDeviceIP} due to less than 2 interfaces configured with ip dhcp snooping limit rate")
                        print(f"INFO: Skipping device: {validDeviceIP} due to less than 2 interfaces configured with ip dhcp snooping limit rate")
                        continue
                    
                    print(f"Outputs and files successfully created for device {validDeviceIP}.\n")
                    print("For any erros or logs please check Logs -> authLog.txt\n")
                    print(f"Program finished, all the configuration has been applied.")

                except Exception as error:
                    print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
                    authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
                    authLog.error(traceback.format_exc(),"\n")
                    failedDevices(username,validDeviceIP,error)
                    
        except Exception as error:
            print(f"ERROR: An error occurred: {error}\n", traceback.format_exc())
            authLog.error(f"User {username} connected to {validDeviceIP} got an error: {error}")
            authLog.error(traceback.format_exc(),"\n")
            failedDevices(username,validDeviceIP,error)   