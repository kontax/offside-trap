import os
from struct import unpack, pack
from subprocess import check_output

from elf_enums import ELFFileType
from elf_parser import ELF

BYTES_TO_SAVE = 0xf
TABLE_ENTRY_SIZE = 0x20
PREAMBLE_BYTECODE = bytearray([0x68, 0x00, 0x00, 0x00, 0x00,                # push [table_offset]
                               0x50,                                        # push rax
                               0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00,    # lea rax, [addr]
                               0xff, 0xe0])                                 # jmp rax


class ELFPacker:
    def __init__(self, binary):
        print(os.getcwd())
        self.filename = binary
        self.binary = ELF(binary)

        # If the binary is not position independent, it starts at this set offset
        self._pie_offset = 0 if self.binary == ELFFileType.ET_DYN else 0x400000

    def list_functions(self):
        """
        Lists all the functions available to encrypt within the binary.

        :return: A list of Function objects with the binary
        """
        return self.binary.list_functions()

    def encrypt(self, encryption_key, function_list):
        """
        Encrypts the functions selected with the encryption key provided, as well as creating a new segment to place
        the encryption/decryption routines into.

        :param encryption_key: The key used to encrypt the selected functions
        :param function_list: The list of functions to encrypt
        """
        print(f"Encrypting {function_list} in {self.binary} with {encryption_key}")

        # Construct the table used for reference in the decryption/encryption routines
        table = self._get_reference_table(function_list)
        table_size = table.count(',') + 1  # Counts the number of comma's (bytes) within the table
        for function in function_list:
            self._encrypt_function(function, encryption_key)

        # Create a segment to load the routines in
        null_data = b'\x00' * (table_size + 400)
        segment = self.binary.append_loadable_segment(null_data)

        # Set up and assemble the encryption/decryption routines
        loader = self._assemble_loader(table, segment)

        # Add the call to encryption routine at the start of each function, ensuring the correct addresses/offsets
        # are used
        decryption_addr = loader.find(b'PSQ')  # Finds the first occurrence of this sequence of bytes
        i = 0
        while i < len(function_list):
            self._write_new_preamble(i, function_list[i], decryption_addr)
            i += 1

        # Place the bytecode of the assembled loader into the newly created segment
        start = segment.p_offset
        end = start + len(loader)
        self.binary.data[start:end] = loader

        # Make text section writeable
        # TODO: This shouldn't be necessary
        text_segment = [s for s in self.binary.segments
                        if '.text' in [sec.name for sec in s.sections]][0]
        text_segment.p_flags = 7

        # Save the packed elf
        with open(f"{self.filename}.packed", "wb") as f:
            f.write(self.binary.data)

    def _get_reference_table(self, function_list):
        """
        Creates a list of bytearray's representing the lookup table for the encryption/decryption routines.

        :param function_list: The list of functions selected for encryption
        :return: A string with comma's separating each byte representing the lookup table
        """
        table = []
        selected_functions = [f for f in self.list_functions() if f.name in function_list]
        for function in selected_functions:
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
        start_addr = function.start - self._pie_offset
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

    def _assemble_loader(self, table, segment):
        """
        Assembles the encryption/decryption routine loader after replacing placeholder values with those calculated
        within the binary and selected functions, and returns the bytecode of the assembled code.
        :param table: The reference table used to lookup encrypted function details
        :param segment: The segment created to load the bytecode into
        :return: A bytearray containing the bytecode of the assembled loader
        """
        loader_file = 'asm/loader.asm'
        text = self.binary.get_section('.text')
        with open(loader_file) as f:
            loader = f.read()

        loader = loader.replace("#TEXT_START#", f"{hex(text.sh_addr)}") \
            .replace("#TEXT_LEN#", f"{hex(text.sh_size)}") \
            .replace("#OEP#", f"{hex(self.binary.e_entry)}")

        # Load the default preamble bytes into the loader
        preamble = PREAMBLE_BYTECODE.copy()
        loader = loader.replace("#PREAMBLE#", ','.join(f'0x{x:02x}' for x in preamble)) \
            .replace("#BIN_OFFSET#", str(segment.p_vaddr))

        # Prepend the table string to the loader
        loader = loader.replace("#TABLE#", table)
        with open(f"{loader_file}.new", 'w') as f:
            f.write(loader)

        # Assemble the loader
        output = f"{loader_file}.out"
        check_output(['nasm', loader_file, '-o', output])

        # Read the bytecode of the assembled loader
        loader_bytes = bytearray(open(output, 'rb').read())
        os.remove(output)
        return loader_bytes

    def _write_new_preamble(self, index, function, decryption_addr):
        offset = pack('I', index)
        # TODO: Why is this 5 again??
        jump = pack('I', (decryption_addr - self._pie_offset) - (function.start_addr - self._pie_offset) - 5)

        bytecode = PREAMBLE_BYTECODE.copy()
        bytecode[1:5] = offset
        bytecode[9:13] = jump

        # Replace the function preamble with the new bytes
        start = function.start_addr - self._pie_offset
        end = start + BYTES_TO_SAVE
        assert (BYTES_TO_SAVE == len(bytecode))
        self.binary.data[start:end] = bytecode
