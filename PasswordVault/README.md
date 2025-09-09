# Simple Encrypted Password Vault in C Lang

##  Goal
Build a minimal password manager in C that:
- Stores service/username/password entries.
- Encrypts them with a master password before writing to disk.
- Allows secure retrieval after master password verification.

This project is educational: it demonstrates 
- Secure coding in C (file I/O, memory, structs).
- Basics of encryption (AES-GCM + PBKDF2).
- Why weak key management (like XOR) is insecure.



##  Features
- `init` → Create a new encrypted vault file.
- `add` → Add a new service/username/password.
- `list` → Show stored service names only.
- `show` → Decrypt and display credentials for a chosen service.
- `rekey` → Change master password (re-encrypt vault).
- **Educational XOR demo** → show why weak crypto fails.

---

##  Tech Stack
- Language: C (C99)
- Libraries: OpenSSL (AES, PBKDF2, RNG)
- Platform: Linux (tested on Kali)
- Build: `make`

---

##  Learning Objectives
1. Practice **C programming fundamentals** (memory management, strings, arrays).
2. Understand **cryptographic concepts**:
   - Symmetric encryption (AES-GCM).
   - Key derivation from passwords (PBKDF2).
   - Salt, nonce (IV), authentication tag.
3. Explore **secure coding practices**:
   - Error handling.
   - File permissions (0600).
   - Zeroization of secrets in memory.
4. Compare **strong crypto vs weak crypto (XOR demo)**.

---

## ⚠️ Disclaimer
This is **not** a production password manager.  
It is a **learning project** to understand secure coding and encryption in C.

