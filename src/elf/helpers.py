from struct import unpack, pack


def is_string_hex(string):
    try:
        int(string, 16)
        return True
    except ValueError:
        return False


def parse_string_data(data, offset):
    string_array = []
    i = offset
    while data[i] != "\x00":
        string_array.append(data[i])
        i += 1

    return ''.join(string_array)


def parse_struct(data, ent_num, h_offset, ent_size, struct_fmt):
    """ Parses an ELF structure to return the values based on the struct format string.

    :param data: Full bytearray of the binary
    :param ent_num: Entity number to count from the offset, ie. the n'th entry of the table
    :param ent_size: Size of an individual entry in the structure in bytes
    :param h_offset: Offset in bytes from the start of the binary that the start of the structure is located
    :param struct_fmt: The struct format string
    :return: A tuple containing the formatted data
    """
    # entsize is the size in bytes of the entity
    inner_offset = ent_num * ent_size
    start_offset = h_offset + inner_offset
    end_offset = start_offset + ent_size

    # Extract the header data from the full data
    extract_data = data[start_offset:end_offset]
    return unpack(struct_fmt, extract_data)


def set_struct(data, ent_num, ent_size, ent_offset, struct_fmt, idx, value):
    bytearray_data = list(parse_struct(data, ent_num, ent_offset, ent_size, struct_fmt))
    bytearray_data[idx] = value
    offset = ent_offset + (ent_num * ent_size)
    repack(data, offset, ent_size, bytearray_data, struct_fmt)


def repack(full_data, offset, size, data_segment, struct):
    """ Rebuilds the binary data with any changes that may have occurred.
    
    :param full_data: The full bytearray for the binary
    :param offset: The offset in bytes of the data being updated within the full data
    :param size: The size in bytes of the data being updated
    :param data_segment: The value of the updated segment of data
    :param struct: Format of the data to be packed
    """
    end_offset = offset + size
    full_data[offset:end_offset] = pack(struct, *data_segment)
