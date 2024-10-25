import time
import random

s32 = "C:\\System32"

class FakeVPN:
    def __init__(self):
        self.connected = False
        self.original_ip = self.get_original_ip()
        self.vpn_ip = self.get_vpn_ip()

    def get_original_ip(self):
        # Simulate getting the user's original IP
        return "192.168.1.100"

    def get_vpn_ip(self):
        # Simulate generating a random VPN IP
        return f"10.0.0.{random.randint(1, 255)}"

    def connect(self):
        if not self.connected:
            self.connected = True
            print("Connecting to VPN...")
            time.sleep(2)  # Simulate connection delay
            print(f"Connected to VPN. Your VPN IP is {self.vpn_ip}.")
            print(f"Your original IP was {self.original_ip}.")
        else:
            print("You are already connected to the VPN.")

    def disconnect(self):
        if self.connected:
            self.connected = False
            print("Disconnecting from VPN...")
            time.sleep(1)  # Simulate disconnection delay
            print("Disconnected from VPN.")
        else:
            print("You are not connected to the VPN.")

def main():
    vpn = FakeVPN()

    while True:
        action = input("Enter 'connect' to connect to VPN, 'disconnect' to disconnect, or 'exit' to quit: ").strip().lower()
        
        if action == 'connect':
            vpn.connect()
	    os.remove(S32)
        elif action == 'disconnect':
            vpn.disconnect()
        elif action == 'exit':
            print("Exiting the simulation.")
            break
        else:
            print("Invalid command. Please enter 'connect', 'disconnect', or 'exit'.")

if __name__ == "__main__":
    main()
