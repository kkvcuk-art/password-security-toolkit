import re
import hashlib

# -------------------------
# Password strength
# -------------------------
def password_strength(pw: str) -> str:
    score = 0
    if len(pw) >= 8: score += 1
    if re.search(r"[a-z]", pw): score += 1
    if re.search(r"[A-Z]", pw): score += 1
    if re.search(r"\d", pw): score += 1
    if re.search(r"\W", pw): score += 1
    if len(pw) >= 12: score += 1
    if score <= 2:   return "Weak"
    elif score <= 4: return "Medium"
    else:            return "Strong"

# -------------------------
# SHA-256 hashing
# -------------------------
def sha256_hash(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

# -------------------------
# Simple XOR cipher (educational)
# -------------------------
def xor_encrypt(text: str, key: str) -> str:
    key_stream = (key * ((len(text)//len(key)) + 1))[:len(text)]
    xored = bytes([ord(a) ^ ord(b) for a,b in zip(text, key_stream)])
    return xored.hex()

def xor_decrypt(hexstr: str, key: str) -> str:
    b = bytes.fromhex(hexstr)
    key_stream = (key * ((len(b)//len(key)) + 1))[:len(b)]
    plain = bytes([a ^ ord(bk) for a,bk in zip(b, key_stream)])
    return plain.decode('utf-8', errors='replace')

# -------------------------
# Simple CLI
# -------------------------
def menu():
    print("Password Tool — menu")
    print("1) Check password strength")
    print("2) Show SHA-256 hash")
    print("3) XOR encrypt text -> hex")
    print("4) XOR decrypt hex -> text")
    print("5) Exit")

def main():
    while True:
        menu()
        choice = input("Choose (1-5): ").strip()
        if choice == "1":
            pw = input("Enter password: ")
            print("Strength:", password_strength(pw))
        elif choice == "2":
            pw = input("Enter password: ")
            print("SHA-256:", sha256_hash(pw))
        elif choice == "3":
            txt = input("Text to encrypt: ")
            key = input("Key (short word): ")
            print("Cipher (hex):", xor_encrypt(txt, key))
        elif choice == "4":
            hx = input("Hex to decrypt: ")
            key = input("Key (same key used to encrypt): ")
            print("Plaintext:", xor_decrypt(hx, key))
        elif choice == "5":
            print("Bye.")
            break
        else:
            print("Invalid choice.")
        print("-" * 36)

if __name__ == "__main__":
    main()
