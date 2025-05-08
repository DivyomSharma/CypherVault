import os
import json
import pyperclip
from colorama import init, Fore, Style
from tqdm import tqdm
from crypto_utils import CryptoUtils

init()  # Initialize colorama

class CypherVault:
    def __init__(self):
        self.crypto = CryptoUtils()
        self.vault_file = "vault.dat"
        self.entries = {}
        self.master_password = None

    def setup(self):
        """Initial setup of the vault."""
        if not os.path.exists(self.vault_file):
            print(f"{Fore.YELLOW}Welcome to CypherVault!{Style.RESET_ALL}")
            self.master_password = input(f"{Fore.CYAN}Create a master password: {Style.RESET_ALL}")
            self.crypto.derive_key(self.master_password)
            self.save_vault()
        else:
            self.load_vault()

    def save_vault(self):
        """Save encrypted vault data."""
        if not self.crypto.fernet:
            raise ValueError("Vault not initialized")
        
        encrypted_data = self.crypto.encrypt_data(json.dumps(self.entries))
        with open(self.vault_file, 'wb') as f:
            f.write(encrypted_data)

    def load_vault(self):
        """Load and decrypt vault data."""
        if not os.path.exists(self.vault_file):
            return

        with open(self.vault_file, 'rb') as f:
            encrypted_data = f.read()

        try:
            self.master_password = input(f"{Fore.CYAN}Enter master password: {Style.RESET_ALL}")
            self.crypto.derive_key(self.master_password)
            decrypted_data = self.crypto.decrypt_data(encrypted_data)
            self.entries = json.loads(decrypted_data)
        except Exception as e:
            print(f"{Fore.RED}Error: Invalid master password or corrupted vault{Style.RESET_ALL}")
            exit(1)

    def add_entry(self):
        """Add a new password entry."""
        service = input(f"{Fore.CYAN}Service/Website: {Style.RESET_ALL}")
        username = input(f"{Fore.CYAN}Username: {Style.RESET_ALL}")
        password = input(f"{Fore.CYAN}Password: {Style.RESET_ALL}")
        
        self.entries[service] = {
            "username": username,
            "password": password
        }
        self.save_vault()
        print(f"{Fore.GREEN}Entry added successfully!{Style.RESET_ALL}")

    def get_entry(self):
        """Retrieve a password entry."""
        service = input(f"{Fore.CYAN}Enter service/website name: {Style.RESET_ALL}")
        if service in self.entries:
            entry = self.entries[service]
            print(f"\n{Fore.GREEN}Username: {entry['username']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Password: {entry['password']}{Style.RESET_ALL}")
            pyperclip.copy(entry['password'])
            print(f"{Fore.YELLOW}Password copied to clipboard!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Entry not found!{Style.RESET_ALL}")

    def list_entries(self):
        """List all stored entries."""
        if not self.entries:
            print(f"{Fore.YELLOW}No entries found in vault.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Stored Entries:{Style.RESET_ALL}")
        for service in self.entries:
            print(f"{Fore.GREEN}• {service}{Style.RESET_ALL}")

    def encrypt_file(self):
        """Encrypt a file."""
        input_file = input(f"{Fore.CYAN}Enter file path to encrypt: {Style.RESET_ALL}")
        if not os.path.exists(input_file):
            print(f"{Fore.RED}File not found!{Style.RESET_ALL}")
            return

        output_file = input_file + ".encrypted"
        try:
            with tqdm(total=100, desc="Encrypting") as pbar:
                self.crypto.encrypt_file(input_file, output_file)
                pbar.update(100)
            print(f"{Fore.GREEN}File encrypted successfully!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error encrypting file: {str(e)}{Style.RESET_ALL}")

    def decrypt_file(self):
        """Decrypt a file."""
        input_file = input(f"{Fore.CYAN}Enter encrypted file path: {Style.RESET_ALL}")
        if not os.path.exists(input_file):
            print(f"{Fore.RED}File not found!{Style.RESET_ALL}")
            return

        output_file = input_file.replace(".encrypted", ".decrypted")
        try:
            with tqdm(total=100, desc="Decrypting") as pbar:
                self.crypto.decrypt_file(input_file, output_file)
                pbar.update(100)
            print(f"{Fore.GREEN}File decrypted successfully!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error decrypting file: {str(e)}{Style.RESET_ALL}")

    def run(self):
        """Main program loop."""
        self.setup()
        
        while True:
            print(f"\n{Fore.CYAN}CypherVault Menu:{Style.RESET_ALL}")
            print("1. Add password entry")
            print("2. Get password entry")
            print("3. List all entries")
            print("4. Encrypt file")
            print("5. Decrypt file")
            print("6. Exit")
            
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-6): {Style.RESET_ALL}")
            
            if choice == "1":
                self.add_entry()
            elif choice == "2":
                self.get_entry()
            elif choice == "3":
                self.list_entries()
            elif choice == "4":
                self.encrypt_file()
            elif choice == "5":
                self.decrypt_file()
            elif choice == "6":
                print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")

if __name__ == "__main__":
    vault = CypherVault()
    vault.run() 