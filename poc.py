# Identify location of the NOP function
# Find address of all functions to be encrypted
# Calculate table based on the address and number of those functions
# Encrypt the functions
# Load the bytes for the table at the start of the loader
# Calculate address of various functions in loader:
#  - entry
#  - decrypt
#  - encrypt
# Add the call to encryption routine at the start of each function, ensuring the correct addresses/offsets are used
# Parse assembly file and replace the following variables
#  - table address
#  - text_start
#  - text_len
#  - oep
# Load in loader to the address of NOP
# Change OEP

from struct import pack, unpack
from elf_parser import ELF
from elf_enums import SymbolType

BYTES_TO_SAVE = 25
XOR = 0xa5


def get_nop_function(elf):
    return [s for s in elf.segments if s.symbol_name == 'nop']


def get_functions_for_encryption(elf):
    func_symbols = [f for f in elf.symbols
                    if f.st_info.st_type == SymbolType.STT_FUNC  # All functions
                    and elf.data[f.st_value:f.st_value+4] == "\x55\x48\x89\xe5"]  # Have preamble
    return func_symbols


def get_bytes_to_save(elf, function):
    data = elf.data[function.st_value:function.st_value+BYTES_TO_SAVE]
    padding = bytearray(b'\0'*7)
    data[len(data):] = padding
    return data


def calculate_address(st_value):
    return st_value + 0x400000


def create_table_entry(bytes_to_save, st_size, func_addr):
    entry = bytearray(48)
    entry[0:32] = bytes_to_save
    entry[32:40] = unpack("8b", pack("Q", st_size))
    entry[40:] = unpack("8b", pack("Q", func_addr))
    return entry


def main(filename):
    elf = ELF(open(filename, 'rb').read())

    # Get nop function for overwriting
    nop = get_nop_function(elf)

    # Find address of all functions to be encrypted
    functions = get_functions_for_encryption(elf)

    # Calculate table based on the address and number of those functions
    i = 0
    table = []
    while i < len(functions):
        function = functions[i]
        bytes_to_save = get_bytes_to_save(elf, function)
        func_addr = calculate_address(function.st_value)
        table_entry = create_table_entry(bytes_to_save, function.st_size, func_addr)
        table.append(table_entry)

        # Encrypt the function's data
        start = function.st_value
        end = start + function.st_size
        for j in range(start, end):
            elf.data[j:j] = elf.data[j:j] ^ XOR

        i += 1

    # Load the bytes for the table at the start of the loader
    table_array = []
    for entry in table:
        table_array.append(' '.join('{:02x}'.format(x) for x in entry))
    table_str = ' '.join(x for x in table_array)

    # Prepend the table string to the loader



