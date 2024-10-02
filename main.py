from utils import mkdir


import os

def main():
    mkdir()
    from strings import greetingString, menuString, inputErrorString, menuOrg
    greetingString()
    from auth import Auth
    from functions import checkIsDigit
    from commandsCLI import complCheckCaremore, complCheckElevance
    from log import authLog
    
    validIPs, username, netDevice = Auth()
    
    while True:
    
        menuOrg()
        selection = input("Please choose the option that you want: ")
        if checkIsDigit(selection):
            if selection == "1":
                while True:
                    menuString(validIPs, username), print("\n")
                    print(f"INFO: Organization: Elevance")
                    selection = input("Please choose the option that you want: ")
                    if checkIsDigit(selection):
                        if selection == "1":
                            # This option will check compliance on the device
                            complCheckElevance(validIPs, username, netDevice)
                        if selection == "2":
                            authLog.info(f"User {username} disconnected from the devices {validIPs}")
                            authLog.info(f"User {username} logged out from the program.")
                            
                            break
                    else:
                        authLog.error(f"Wrong option chosen, you input: {selection}")
                        inputErrorString()
                        os.system("PAUSE")
                break
                    
            if selection == "2":
                while True:
                    menuString(validIPs, username), print("\n")
                    print(f"INFO: Organization: Caremore")
                    selection = input("Please choose the option that you want: ")
                    if checkIsDigit(selection):
                        if selection == "1":
                            # This option will check compliance on the device
                            complCheckCaremore(validIPs, username, netDevice)
                        if selection == "2":
                            authLog.info(f"User {username} disconnected from the devices {validIPs}")
                            authLog.info(f"User {username} logged out from the program.")
                            break
                    else:
                        authLog.error(f"Wrong option chosen, you input: {selection}")
                        inputErrorString()
                        os.system("PAUSE")
                break

            if selection == "3":
                authLog.info(f"User {username} disconnected from the devices {validIPs}")
                authLog.info(f"User {username} logged out from the program.")
                break
        else:
            authLog.error(f"Wrong option chosen, you input: {selection}")
            inputErrorString()
            os.system("PAUSE")

if __name__ == "__main__":
    main()