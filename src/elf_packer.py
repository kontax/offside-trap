import os
import stat
from struct import unpack, pack
from subprocess import check_output

from elf.enums import ELFFileType
from elf.parser import ELF

BYTES_TO_SAVE = 0xf
TABLE_ENTRY_SIZE = 0x20
PREAMBLE_BYTECODE = bytearray([0x68, 0x00, 0x00, 0x00, 0x00,  # push [table_offset]
                               0x50,  # push rax
                               0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00,  # lea rax, [addr]
                               0xff, 0xe0])  # jmp rax


class ELFPacker:
    def __init__(self, binary):
        self.filename = binary
        self.binary = ELF(binary)
        self.functions = None

        # If the binary is not position independent, it starts at this set offset
        self._pie_offset = 0 if self.binary.e_type == ELFFileType.ET_DYN else 0x400000

    def list_functions(self):
        """
        Lists all the functions available to encrypt within the binary.

        :return: A list of Function objects with the binary
        """
        if self.functions is None:
            self.functions = self.binary.list_functions()
        return self.functions

    def encrypt(self, encryption_key, function_list):
        """
        Encrypts the functions selected with the encryption key provided, as well as creating a new segment to place
        the encryption/decryption routines into.

        :param encryption_key: The key used to encrypt the selected functions
        :param function_list: The list of functions to encrypt
        """
        function_list.sort(key=lambda fn: fn.name)
        overlapping = self._get_overlapping_functions(function_list)
        to_remove = []
        print(f"[*] Encrypting the following functions in {self.filename} with {encryption_key}")
        for f in function_list:
            if f.size < BYTES_TO_SAVE:
                print(f"\t- {f} : Function is too small")
                to_remove.append(f)
            elif f in to_remove:
                print(f"\t- {f} : Function is overlapping with another")
            elif f.name == "_start" or 'libc' in f.name or '_dl_' in f.name:
                print(f"\t- {f} : Ignoring")
                to_remove.append(f)
            else:
                print(f"\t+ {f}")

        print()

        to_remove.extend(overlapping)

        # Remove any functions that overlap or have been flagged
        for f in to_remove:
            function_list.remove(f)

        # Construct the table used for reference in the decryption/encryption routines
        print('[*] Encrypting functions')
        table = self._get_reference_table(function_list)
        table_size = table.count(',') + 1  # Counts the number of comma's (bytes) within the table
        for function in function_list:
            self._encrypt_function(function, encryption_key)

        # Create a segment to load the routines in
        print("[*] Creating new segment to load encryption/decryption routines in")
        segment = self.binary.append_loadable_segment_3(table_size + 400)

        # Set up and assemble the encryption/decryption routines
        loader = self._assemble_loader(table, segment, encryption_key)

        # Add the call to encryption routine at the start of each function, ensuring the correct addresses/offsets
        # are used
        search_str = b"\x58\x68\xff\xff\xff\x0f\x68\xff\xff\xff\x0f"  # Bytecode at start of encryption function
        decryption_addr = loader.find(search_str) + segment.p_vaddr
        i = 0
        while i < len(function_list):
            self._write_new_preamble(i, sorted(function_list, key=lambda fn: fn.name)[i], decryption_addr)
            i += 1

        # Place the bytecode of the assembled loader into the newly created segment
        start = segment.p_offset
        end = start + len(loader)
        self.binary.data[start:end] = loader

        # Modify the entry to point into the new segment we've created, allowing for the text section to
        # become RWX using mprotect()
        new_entry = segment.p_vaddr + 8
        print(f"[*] Entry moved from {hex(self.binary.e_entry)} to {hex(new_entry)}")
        self.binary.e_entry = new_entry

        # Save the packed elf and set the executable bit
        print(f"[*] Saving file as {self.filename}.packed and making it executable")
        with open(f"{self.filename}.packed", "wb") as f:
            f.write(self.binary.data)

        st = os.stat(f"{self.filename}.packed")
        os.chmod(f"{self.filename}.packed", st.st_mode | stat.S_IEXEC)
        print()

    def _get_reference_table(self, function_list):
        """
        Creates a list of bytearray's representing the lookup table for the encryption/decryption routines.

        :param function_list: The list of functions selected for encryption
        :return: A string with comma's separating each byte representing the lookup table
        """
        table = []
        i = 0
        for function in function_list:
            i += 1
            entry = self._get_table_entry(function)
            entry_str = ','.join("0x{:02x}".format(x) for x in entry)
            table.append(entry_str)

        # Convert the table array to a string
        return ','.join(x for x in table)

    def _get_table_entry(self, function):
        """
        Create a bytearray containing an entry to the loader table, populating the bytes to save, size and address
        of the function being encrypted.

        :param function: The Function object to create a table entry for
        :return: A bytearray containing a single entry to the decryption lookup table
        """
        # Encrypt and store first bytes
        start_addr = function.start_addr - self._pie_offset
        end_addr = start_addr + BYTES_TO_SAVE
        bytes_to_save = self.binary.get_data_segment(start_addr, end_addr)

        # Create an entry within the table
        entry = bytearray(TABLE_ENTRY_SIZE)
        entry[0:16] = bytes_to_save  # The bytes overwritten by the encryption preamble
        entry[16:24] = unpack("8B", pack("Q", function.size))  # The size of the function
        entry[24:] = unpack("8B", pack("Q", function.start_addr))  # The offset of the function within memory

        return entry

    def _encrypt_function(self, function, encryption_key):
        """
        Encrypts a single function with the specified key.

        :param function: The Function object to encrypt
        :param encryption_key: The key to encrypt the function with
        """
        start = function.start_addr - self._pie_offset
        end = start + function.size

        for j in range(start, end):
            self.binary.data[j] = self.binary.data[j] ^ encryption_key

    def _assemble_loader(self, table, segment, key):
        """
        Assembles the encryption/decryption routine loader after replacing placeholder values with those calculated
        within the binary and selected functions, and returns the bytecode of the assembled code.
        :param table: The reference table used to lookup encrypted function details
        :param segment: The segment created to load the bytecode into
        :param key: Encryption key used to encrypt/decrypt the data
        :return: A bytearray containing the bytecode of the assembled loader
        """
        filename = 'asm/loader.asm'
        dirname = os.path.dirname(__file__)
        loader_file = os.path.join(dirname, filename)
        text_segment = [s for s in self.binary.segments
                        if '.text' in [sec.section_name for sec in s.sections]][0]
        with open(loader_file) as f:
            loader = f.read()

        loader = loader.replace("#TEXT_START#", f"{hex(text_segment.p_vaddr)}") \
            .replace("#TEXT_LEN#", f"{hex(text_segment.p_memsz)}") \
            .replace("#OEP#", f"{hex(self.binary.e_entry)}") \
            .replace("#KEY#", f"{hex(key)}")

        # Load the default preamble bytes into the loader
        preamble = PREAMBLE_BYTECODE.copy()
        loader = loader.replace("#PREAMBLE#", ','.join(f'0x{x:02x}' for x in preamble)) \
            .replace("#BIN_OFFSET#", str(hex(segment.p_vaddr)))

        # Prepend the table string to the loader
        loader = loader.replace("#TABLE#", table)
        with open(f"{loader_file}.new", 'w') as f:
            f.write(loader)

        # Assemble the loader
        output = f"{loader_file}.out"
        check_output(['nasm', f"{loader_file}.new", '-o', output])

        # Read the bytecode of the assembled loader
        loader_bytes = bytearray(open(output, 'rb').read())
        os.remove(output)
        return loader_bytes

    def _write_new_preamble(self, index, function, decryption_addr):
        """
        Replaces the initial few bytes of each encrypted function with bytecode used to jump into the
        decryption routine.

        :param index: The index of the function within the lookup table
        :param function: The function object being encrypted
        :param decryption_addr: The address of the decryption routine within the binary
        """
        offset = pack('I', index)

        # Calculate the offset of the function based on the relative position
        preamble_offset = len(PREAMBLE_BYTECODE) - 2  # 'jmp rax' is 2 bytes, which needs to be removed
        decr = decryption_addr - self._pie_offset
        start = function.start_addr - self._pie_offset
        jump = pack('I', decr - start - preamble_offset)

        # Modify the bytecode to take the relative positions
        bytecode = PREAMBLE_BYTECODE.copy()
        bytecode[1:5] = offset
        bytecode[9:13] = jump

        # Replace the function preamble with the new bytes
        start = function.start_addr - self._pie_offset
        end = start + BYTES_TO_SAVE
        assert (BYTES_TO_SAVE == len(bytecode))
        self.binary.data[start:end] = bytecode

    @staticmethod
    def _get_overlapping_functions(function_list):
        """
        Pulls out any functions that may be overlapping. This may occur when the function analysis does not correctly
        deduce where a function begins or ends.

        :param function_list: The original list of functions
        :return: A list of functions that are overlapping
        """
        overlapping = []
        for f1 in function_list:
            for f2 in function_list:
                if f1 is f2:
                    continue
                if (f1.start_addr > f2.start_addr and f1.end_addr < f2.end_addr) or \
                        (f2.start_addr < f1.start_addr < f2.end_addr) or \
                        (f1.start_addr < f2.start_addr and f1.end_addr > f2.end_addr) or \
                        (f1.start_addr < f2.start_addr < f1.end_addr):
                    if f1 not in overlapping:
                        overlapping.append(f1)
                    if f2 not in overlapping:
                        overlapping.append(f2)

        for f in overlapping:
            function_list.remove(f)

        return overlapping
