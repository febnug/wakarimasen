import sys

def restore_elf(file):
    with open(file, "rb") as f:
        data = bytearray(f.read())

    if data[:4] == b'\x7fLEL':
        data[1:4] = b'ELF'
        with open(file, "wb") as f:
            f.write(data)
        print(f"[✔] File dipulihkan ke ELF: {file}")
    else:
        print("[!] Bukan file LELF")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file>")
        sys.exit(1)
    restore_elf(sys.argv[1])
