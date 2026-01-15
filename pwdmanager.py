
import base64, os
import getpass
import secrets, string
import re
import pyotp, qrcode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

# Core problem that we are solving is that user passwords are usually messy
# and not strong enough and attackers can easily guess them. that is why, we are 
# using fernet encryption to store passwords in an encrypted format. however,
# fernet does not just take the passwords in directly, and we need to convert the 
# passwords into a key that fernet can use and is exactly 32 bytes, encoded in base-64 format.

# Step-by-Step breakdown:
# 1) We will create the PBKDF2HMAC object

# Think of it as setting up a machine that will transform password into keys
# The algorithm we will use is SHA256
# The length of the key will be 32 bytes
# We will use a salt, which is a sequence of random bytes, which ensure that
# even if two users have the same password, their derived keys will be different
# if they have two unique salts
# The number of iterations is set to 480,000, which means that it will hash the password
# and the salt together 4800000 times to make it more secure against brute-force attacks

# 2)
# next, we need to convert the password into bytes itself, because cryptographic
# functions don't understand strings directly.

# 3)
# derive the raw key

# here we will use our initial string encoded into bytes
# then merge it with the salt
# then we will run the hashing 480000 times to produce 32 bytes of cryptographically strong output
# this step ensures that the same salt and same password will always produce the same key
# (THIS STEP IS DETERMINISTIC)

# 4)
# next, we need to encode the derived key into a format that fernet can use as well as
# so that it is URL-safe and base64-encoded because sometimes there can be special characters
# that can cause issues when transmitting data over the internet or storing it in a certain format

# to achieve this, we will use base64's method which is urlsafe_b64encode that will convert 
# this into 44 bytes of clean ASCII characters that fernet can use

# 5)
# now we have a perfect fernet key that can be used

# WHY THIS APPROACH IS SO GOOD:
# even weak passwords such as "cat" are now cryptographically strong keys
# these keys are hashed 480000 times which makes it much more computationally expensive for hackers to guess them with brute-force
# they are resistant to rainbow table attacks because of the unique salt (rainbow tables are precomputed tables used to reverse cryptographic hash functions)
# they are deterministic but irreversible, meaning that the same password and salt will always produce the same key, but you cannot easily go back from the key to the original password




def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a Fernet encryption key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 480000
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)



# Here, what we are doing is loading the salt from a file if it already exists
# or creating a new random 16 byte salt and writing it to the salt.salt File
# if the file does not exist, then we need to handle the FileNotFoundError exception 
# with the try and except Block


def load_or_generate_salt():
    """Loads existing salt or generates a new one if none exists."""
    try:
        with open("salt.salt", "rb") as salt_file:
            salt = salt_file.read()
    except FileNotFoundError:
        salt = os.urandom(16) #generate a 16 byte random salt
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    return salt

def generate_password(length = 16):
    """Generates a cryptographically secure random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    pwd = ''
    for i in range(length):
        pwd += secrets.choice(characters)
    return pwd
    

def view():
    """Displays all stored passwords."""
    try:
        with open('passwords.txt', 'r') as f:
            for line in f.readlines():
                line = line.rstrip() # removes the new line character that we added to the end of each line
                user, pwd = line.split("|") # we are splitting the line into a list of two elements, the user and the password since we added them to the file with a | operator
                # Decrypt returns bytes, so we decode to get a string
                decrypted_pwd = fer.decrypt(pwd.encode()).decode()
                print(f"User: {user} | Password: {decrypted_pwd}")
    except FileNotFoundError:
        print("No passwords stored yet.")
    except InvalidToken as e:
        print("Incorrect master password or corrupted data.")
    except Exception as e:
        print(f"An error occurred: {e}")


def add():
    """Adds a new password to the vault."""
    name = input('Account Name: ')
    # pwd = input('Password: ')
    choice = input('Generate password or enter manually? (g/m): ').lower()
    if choice == 'g':
        length_input = input('Password length (press Enter for 16): ')

        if(length_input == ''):
            length = 16
        else:
            try:
                length = int(length_input)
                if(length < 4):
                    print("Length too short, setting to length 16")
                    length = 16
            except ValueError:
                print("Invalid input, setting length to 16")
                length = 16
        pwd = generate_password(length)
        print(f"Generated Password: {pwd}")
    else:
        pwd = input('Password: ')
        strength, suggestions = check_strength(pwd)
        print(f"Password Strength: {strength}")
        if suggestions:
            for suggestion in suggestions:
                print("\n" + suggestion)
            print("\nConsider using a stronger password and try again.")
            add()
        
        


    with open('passwords.txt', 'a') as f:
        # Encrypt returns bytes, so we decode to store as string
        # a is used when you want to add entries to an existing file and if it doesnt exist, it creates it
        # w is used when you want to write to a file but it clears the file first and then writes over it
        # r is used when you want to read from a file
        # therefore in this case we use a to add to the file
        # the with keyword is used when we want to open a file and then it automatically closes it
        encrypted_pwd = fer.encrypt(pwd.encode()).decode()
        f.write(name + "|" + encrypted_pwd + "\n")

def search():
    """Searches for passwords by account name."""
    try:
        search_term = input("Search for account: ").lower()
        
        with open('passwords.txt', 'r') as f:
            # found = False
            matches = []
            for line in f.readlines():
                line = line.rstrip()
                user, pwd = line.split("|")
                if search_term in user.lower():
                    decrypted_pwd = fer.decrypt(pwd.encode()).decode()
                    matches.append((user, decrypted_pwd))
            if(matches):
                print(f"\n--- Found matching accounts for '{search_term}' ---")
                for user, decrypted_pwd in matches:
                    print(f"\nUser: {user} | Password: {decrypted_pwd}")
            else:
                print("No matching accounts found.")
    except FileNotFoundError:
        print("No passwords stored yet.")
    except InvalidToken:
        print("Incorrect master password or corrupted data.")

def delete():
    
    """Deletes a password from the vault."""
    try:
        account_name = input("Enter the exact account name to delete or to delete all passwords, type 'DELETE ALL': ")
        if account_name == 'DELETE ALL':
            confirm = input("Are you sure you want to delete ALL passwords? (y/n): ").lower()
            if confirm == 'y':
                os.remove('passwords.txt')
                return
            else:
                print("Deletion cancelled.")
                return

        with open('passwords.txt', 'r') as f:
            lines = f.readlines()

        new_lines = []
        found = False

        for line in lines:
            user, pwd = line.strip().split("|")
            if user.lower() == account_name.lower():
                confirm = input(f"Are you sure you want to delete '{user}'? (y/n): ").lower()
                if confirm == 'y':
                    found = True
                    print(f"Deleted account '{user}'.")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        if found:
            with open('passwords.txt', 'w') as f:
                f.writelines(new_lines)
        else:
            print("Account not found.")

    except FileNotFoundError:
        print("No passwords stored yet.")
    except InvalidToken:
        print("Incorrect master password or corrupted data.")
    except Exception as e:
        print(f"An error occurred: {e}")

def check_strength(password: str) -> dict:
    """
    Goal: Return a score (0-5) and a list of suggestions.
    Hint: Use the 're' (Regular Expression) module. 
    Check for:
    - Length (min 12?)
    - Presence of [A-Z], [a-z], [0-9]
    - Presence of special characters (punctuation)
    """
    # TODO: Initialize score at 0
    # TODO: Use re.search() to find patterns
    score = 0
    suggestions = []
    if(len(password) >= 12):
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Too short, use at least 8 characters.")

    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")
    
    if re.search(r'[0-9]', password):
        score += 1
    else:
        suggestions.append("Add some numbers.")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        suggestions.append("Add some special characters.")

    levels = {0: "Weak 🔴", 1: "Weak 🔴", 2: "Fair 🟠", 3: "Good 🟡", 4: "Strong 🟢", 5: "Excellent 💎"}


    return levels.get(score, password), suggestions

# read this method very carefully, it is very important 
def change_master_password():
    """Changes the master password and re-encrypts all stored passwords."""
    
    # Step 1: Verify current password by trying to decrypt a test entry
    current_pwd = getpass.getpass("Current Master Password: ")
    current_salt = load_or_generate_salt()
    current_key = derive_key(current_pwd, current_salt)
    current_fer = Fernet(current_key)
    
    # Verify the password is correct by attempting to decrypt existing data
    try:
        with open("passwords.txt", "r") as f:
            lines = f.readlines()
            if not lines:
                print("Vault is empty, nothing to re-encrypt.")
                return
            
            # Test decrypt the first entry to verify password
            first_line = lines[0].strip()
            user, enc_pwd = first_line.split("|")
            test_decrypt = current_fer.decrypt(enc_pwd.encode()).decode()
            
    except FileNotFoundError:
        print("No passwords stored yet.")
        return
    except InvalidToken:
        print("❌ Incorrect current master password. Access denied.")
        return
    except Exception as e:
        print(f"❌ Error: {e}")
        return
    
    # Step 2: Decrypt all passwords into memory
    vault_buffer = {}
    try:
        with open("passwords.txt", "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                user, enc_pwd = line.split("|")
                decrypted_pwd = current_fer.decrypt(enc_pwd.encode()).decode()
                vault_buffer[user] = decrypted_pwd
    except Exception as e:
        print(f"❌ Error reading vault: {e}")
        return
    
    # Step 2.5: Decrypt 2FA secret if it exists
    twofa_secret = None
    if os.path.exists("2fa.config"):
        try:
            with open("2fa.config", "r") as f:
                encrypted_secret = f.read()
                twofa_secret = current_fer.decrypt(encrypted_secret.encode()).decode()
        except Exception as e:
            print(f"⚠️  Warning: Could not decrypt 2FA config: {e}")
            print("    2FA will be disabled. You can re-enable it later.")
    
    # Step 3: Get new password
    new_pwd = getpass.getpass("New Master Password: ")
    new_pwd_confirm = getpass.getpass("Confirm New Master Password: ")
    
    if new_pwd != new_pwd_confirm:
        print("❌ Passwords do not match. Aborting.")
        return
    
    if new_pwd == current_pwd:
        print("❌ New password must be different from current password.")
        return
    
    # Step 4: Derive new key (using SAME salt)
    new_key = derive_key(new_pwd, current_salt)
    new_fer = Fernet(new_key)
    
    # Step 5: Re-encrypt passwords and write back
    try:
        with open("passwords.txt", "w") as f:
            for account, plain_pwd in vault_buffer.items():
                encrypted_pwd = new_fer.encrypt(plain_pwd.encode()).decode()
                f.write(account + "|" + encrypted_pwd + "\n")
    except Exception as e:
        print(f"❌ Error writing vault: {e}")
        return
    
    # Step 5.5: Re-encrypt 2FA secret if it existed
    if twofa_secret:
        try:
            encrypted_secret = new_fer.encrypt(twofa_secret.encode()).decode()
            with open("2fa.config", "w") as f:
                f.write(encrypted_secret)
        except Exception as e:
            print(f"❌ Error re-encrypting 2FA: {e}")
            return
    
    # Step 6: Update global session key
    global fer
    fer = new_fer
    
    print("✅ Master password changed successfully!")
    print("   All passwords have been re-encrypted.")
    if twofa_secret:
        print("   2FA configuration has been re-encrypted.") 

def setup_2fa():
    """Sets up Two-Factor Authentication (2FA) using TOTP."""
    
    # 1. Generate the secret key FIRST
    secret = pyotp.random_base32()
    
    name = input("Enter your desired account name for 2FA: ").strip()
    if not name:
        name = "User@Vault"  # Default name if none provided
    issuer_name = name + " - MySecureVault"
    # 2. Create the standard TOTP URI 
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=name, # You can change this to a dynamic email later
        issuer_name=issuer_name
    )

    print("\n" + "="*20)
    print("   2FA SETUP")
    print("="*20)
    
    # 3. Generate and Print the QR Code
    qr = qrcode.QRCode(version=1, box_size=1, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    
    print("\nScan this QR code with Google Authenticator or Authy:")
    # We need invert = True because usually the terminal background is dark, and it is impossible to scan dark QR codes on dark backgrounds
    qr.print_ascii(invert=True)

    print(f"\nManual Entry Key: {secret}")
    print("-" * 30)

    # 4. Verification Step
    totp = pyotp.TOTP(secret)
    verify_code = input("Enter the 6-digit code from your app to confirm setup: ").strip()

    if totp.verify(verify_code):
        # 5. Encrypt and Save ONLY if verification succeeds
        try:
            encrypted_secret = fer.encrypt(secret.encode()).decode()
            with open("2fa.config", "w") as f:
                f.write(encrypted_secret)
            print("\n✅ 2FA setup successful and enabled!")
        except Exception as e:
            print(f"\n❌ Error saving 2FA config: {e}")
    else:
        print("\n❌ Verification failed. 2FA was NOT enabled. Please try again.")


def check_2fa():
    """Checks Two-Factor Authentication (2FA) code."""
    if not os.path.exists("2fa.config"):
        return True #this means 2fa is not set up yet
    
    with open("2fa.config", "r") as f:
        secret = f.read()
        
    decrypted_secret = fer.decrypt(secret.encode()).decode()
    totp = pyotp.TOTP(decrypted_secret)
    user_code = input("🔐 Enter your 2FA code: ")
    
    return totp.verify(user_code)

def unregister_2fa():
    if not os.path.exists("2fa.config"):
        print("2FA is not set up.")
        return
    
    with open("2fa.config", "r") as f:
        secret = f.read()
        
    decrypted_secret = fer.decrypt(secret.encode()).decode()
    totp = pyotp.TOTP(decrypted_secret)
    checker = input("Enter your current 2FA code to disable 2FA: ")
    if(totp.verify(checker)):
        final_confirm = input("Are you sure you want to disable 2FA? (y/n): ").lower()
        if(final_confirm != 'y'):
            print("2FA disable cancelled.")
            return
        os.remove("2fa.config")
        print("2FA has been disabled.")
    

def display_menu():
    """Displays the main menu."""
    print("\n" + "="*60)
    print(" "*18 + "PASSWORD MANAGER")
    print("="*60)
    print("  [1] View all passwords")
    print("  [2] Add new password")
    print("  [3] Search passwords")
    print("  [4] Delete password")
    print("  [5] Change master password")
    print("  [6] Setup 2FA (if not done already)")
    print("  [7] Disable 2FA (if already set up)")
    print("  [8] Quit")
    print("="*60)

def main():
    """Main program loop."""
    # Initialize encryption
    salt = load_or_generate_salt()
    
    print("\n" + "="*60)
    print(" "*15 + "SECURE PASSWORD MANAGER")
    print("="*60)
    
    master_pwd = getpass.getpass("\n🔐 Enter master password: ")
    
    global fer
    key = derive_key(master_pwd, salt)
    fer = Fernet(key)
    
    if os.path.exists("2fa.config"):
        if not check_2fa():
            print("❌ Invalid 2FA code. Access Denied.")
            return # Exit the program
    
    print("\n✓ Access granted!\n")
    
    # Main loop
    while True:
        display_menu()
        choice = input("\nSelect option (1-8): ").strip()
        
        if choice == '1':
            view()
        elif choice == '2':
            add()
        elif choice == '3':
            search()
        elif choice == '4':
            delete()
        elif choice == '5':
            change_master_password()
        elif choice == '6':
            setup_2fa()
        elif choice == '7':
            unregister_2fa()
        elif choice == '8' or choice.lower() == 'q':
            print("\n👋 Goodbye! Stay secure.\n")
            break
        else:
            print("\n❌ Invalid option. Please choose 1-8.\n")
if __name__ == "__main__":
    main()
