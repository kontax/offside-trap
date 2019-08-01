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


def parse_header(data, entity_number, entsize, h_offset, hdr_struct):
    # entsize is the header size for the entity
    inner_offset = entity_number * entsize
    start_offset = h_offset + inner_offset
    end_offset = start_offset + entsize

    # Extract the header data from the full data
    extract_data = data[start_offset:end_offset]
    return unpack(hdr_struct, extract_data)


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