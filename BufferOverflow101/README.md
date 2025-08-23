# Buffer Overflow 101 (C Language Learning Project)

##  Goal
This project demonstrates a **classic stack buffer overflow** in C and shows how to fix it with secure coding practices.  
The goal is to understand:
- Why buffer overflows happen in C (no automatic bounds checks).
- How unsafe functions like `strcpy` can corrupt memory.
- How to detect overflows using tools (gdb, AddressSanitizer).
- How to rewrite the program safely to prevent the bug.

---

##  What We Did
1. **Created a vulnerable program (`vuln.c`)**
   - Allocates a 32-byte stack buffer.
   - Uses `strcpy` with no bounds check.
   - Overflow occurs when input > 32 characters → overwrites return address → program crashes.

2. **Ran with different inputs**
   - Short input (`Alice`) → program works normally.
   - Long input (200 `B`s) → causes segmentation fault.
   - Verified with **gdb**: the saved return address was overwritten with `0x42424242` (`'B'` in hex).

3. **Created a safe program (`safe.c`)**
   - Uses `strncpy` with size limit (`sizeof(buffer)-1`).
   - Program handles long input safely → no crash.

4. **Used compiler tools**
   - Built with `-fno-stack-protector` to reproduce the crash.
   - Rebuilt with **AddressSanitizer** (`-fsanitize=address`) to catch overflow automatically with detailed error report.

---


