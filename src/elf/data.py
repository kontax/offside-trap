from abc import ABC
from struct import unpack

from elf.enums import DynamicTag, GnuNoteType, RelocationType
from elf.helpers import parse_struct, set_struct


class StructEntity(ABC):
    """ StructEntity
    The StructEntity class is an abstract class used to represent structures within the binary. It allows for getting
    and setting values within the binary on the fly, ensuring that any data that may have changed from an alternative
    location is considered.
    """
    @property
    def data(self):
        """ Gets the byte data that applies to the current structure only """
        return self._data

    @property
    def live_data(self):
        data_start = self.offset + (self.ent_size * self.ent_idx)
        data_end = data_start + self.ent_size
        return ' '.join([f"{s:02x}" for s in self.data[data_start:data_end]])

    @property
    def live_data(self):
        data_start = self.offset + (self.ent_size * self.ent_idx)
        data_end = data_start + self.ent_size
        return self._full_data[data_start:data_end]

    def __init__(self, data, ent_idx, offset, ent_size, struct):
        """ Instantiate a new StructEntity with the relevant properties set.

        :param data: A bytearray containing the full data of the binary
        :param ent_idx: The index of the entity from the base of its parent structure
        :param offset: The offset of the parent structure
        :param ent_size: The size of an entity within the structure
        :param struct: The struct format
        """
        self._full_data = data
        self.ent_idx = ent_idx
        self.offset = offset
        self.ent_size = ent_size
        self.struct = struct

        # Set common properties
        # TODO: Remove data - it's only used for debugging
        data_start = offset + (ent_size * ent_idx)
        data_end = data_start + ent_size
        self._data = ' '.join([f"{s:02x}" for s in data[data_start:data_end]])

    def _get_value(self, idx):
        """ Retrieves a value at the specified index of the struct representation of the data.

        This function applies the struct value specified within the object constructor to the full data at the offset
        also specified in the constructor. The numeric value is then returned from that bytearray.

        :param idx: Index of the struct to return
        :return: A value from within the struct representing the data
        """
        data = parse_struct(self._full_data, self.ent_idx, self.offset, self.ent_size, self.struct)
        return data[idx]

    def _set_value(self, idx, value):
        """ Sets a value at the specified index of the struct representation of the data.

        The struct format from the constructor is applied to the data, with the specified index and value modified
        from there. This new value is then converted back to a bytearray and overwritten in the original binary data.

        :param idx: Index of the struct to modify
        :param value: Value to set the item to
        """
        set_struct(self._full_data, self.ent_idx, self.ent_size, self.offset, self.struct, idx, value)

    @staticmethod
    def _create_numeric_value(data, count, offset, struct, size):
        """ Create's a collection of IntValue objects to use as the bucket/chain

        :param data: Full bytearray data of the binary
        :param count: The number of entries to add
        :param offset: The offset within the binary the list resides
        :return: A list containing IntValue objects
        """
        result = []
        for i in range(count):
            result.append(NumericValue(data, i, offset, size, struct))
            i += 1

        return result


class DynamicTableEntry(StructEntity):
    """ Dynamic Table Entry
    Elf64_Sxword        d_tag   /* Identifies the type of dynamic table entry */
    union {
        Elf64_Xword     d_val   /* Integer value */
        Elf64_Addr      d_ptr   /* Link-time program virtual address */
    } d_un
    """
    @property
    def d_tag(self):
        """ Gets or sets the type of dynamic table entry """
        return DynamicTag(self._get_value(0))

    @d_tag.setter
    def d_tag(self, value):
        self._set_value(0, value.value)

    @property
    def d_un(self):
        """ Gets or sets either a value or dynamic pointer, dependent on the type of entry """
        return self._get_value(1)

    @d_un.setter
    def d_un(self, value):
        self._set_value(1, value)

    def __init__(self, data, entry_idx, offset):
        """ Initializes a new single entry for the dynamic table, containing the type and value.
        TODO: Split out d_ptr and d_val for their respective types

        :param data: The full data of the binary
        :param entry_idx: The index of the entry within the table
        :param offset: The offset in bytes of the start of the table within the binary
        """
        super().__init__(data, entry_idx, offset, 16, 'QQ')

    def __str__(self):
        return f"{self.d_tag}"


class Note(StructEntity):
    """ Note Entry
    Elf64_Word      n_namesz;   /* The length of the name field in bytes */
    Elf64_Word      n_descsz;   /* The length of the descriptor field in bytes */
    Elf64_Word      n_type;     /* The GNU extensions note type */
    """

    @property
    def n_namesz(self):
        """ Gets the size in bytes of the name of the note """
        return self._get_value(0)

    @property
    def n_descsz(self):
        """ Gets the size in bytes of the notes description """
        return self._get_value(1)

    @property
    def n_type(self):
        """ Gets the GNU extensions note type """
        return GnuNoteType(self._get_value(2))

    @property
    def name(self):
        """ Gets the name of the note """
        return self._get_note_name()

    @property
    def desc(self):
        """ Gets the notes description """
        return self._get_note_desc()

    def __init__(self, data, offset):
        """ Initializes a new single entry for the notes table, containing the name, desc and type + sizes.

        :param data: The full data of the binary
        :param offset: The offset in bytes of the entry within the binary
        """
        super().__init__(data, 0, offset, 12, 'III')

    def __str__(self):
        return f"[{self.name}] {self.desc}"

    def _get_note_name(self):
        """ Extracts the value under the note name.
        :return: The utf-8 decoded string containing the note name
        """
        offset = self.offset + 12  # The size of n_namesz, n_descsz and n_type in bytes
        return self._get_note(self.n_namesz, offset).decode('utf-8').replace('\0', '')

    def _get_note_desc(self):
        """ Extracts the value under the note description.
        :return: The note desc value
        """
        padding = self._get_padding_length(self.n_namesz)  # Need to calculate the padding for the name
        offset = self.offset + 12 + padding  # The size of n_namesz, n_descsz and n_type in bytes, plus name padding
        desc = self._get_note(self.n_descsz, offset)

        # Handle GNU specific notes
        if self.name == 'GNU' and self.n_type == GnuNoteType.NT_GNU_ABI_TAG:
            ver = unpack('IIII', desc)
            return f"Linux ABI: {ver[1]}.{ver[2]}.{ver[3]}"
        elif self.name == 'GNU' and self.n_type == GnuNoteType.NT_GNU_BUILD_ID:
            build_id = ''.join(f"{x:02x}" for x in desc)
            return f"Build ID: {build_id}"
        else:
            return ''.join(f"{x:02x}" for x in desc)

    def _get_note(self, size, offset):
        """ Get a note value given the size and offset within the note struct

        :param size: Size of the property to extract
        :param offset: Offset within the note struct
        :return: The value from the bytes data
        """
        entry_idx = 0  # Force the entry index to be zero, as the offset is modified instead
        ent_size = size
        struct = f"{size}s"
        return parse_struct(self._full_data, entry_idx, offset, ent_size, struct)[0]

    @staticmethod
    def _get_padding_length(size_value):
        """ Gets the length in bytes of the padding to use for name or desc to ensure it's aligned

        :param size_value: Size in bytes of the value to pad
        :return: Size of padding to append to be aligned
        """
        # TODO: Extract bit size from ELF header to handle 32 bit binaries
        word_size = 4
        return (word_size - size_value % word_size) % word_size


class HashTable(StructEntity):
    """ SYSV Hash Table
    uint32_t    nbucket;            /* Number of buckets within the table */
    uint32_t    nchain;             /* Number of chains within the table */
    uint32_t    bucket[nbucket];    /* The bucket */
    uint32_t    chain[nchain];      /* The chain */
    """
    @property
    def nbucket(self):
        """ Gets or sets the number of buckets in the table """
        return self._get_value(0)

    @nbucket.setter
    def nbucket(self, value):
        self._set_value(0, value)

    @property
    def nchain(self):
        """ Gets or sets the number of chains in the table """
        return self._get_value(1)

    @nchain.setter
    def nchain(self, value):
        self._set_value(1, value)

    @property
    def bucket(self):
        """ Gets the list of bucket values """
        return self._bucket

    @property
    def chain(self):
        """ Gets the list of chain values """
        return self._chain

    def __init__(self, data, offset):
        """ Instantiates a new HashTable at the offset given.

        :param data: Full bytearray data of the value
        :param offset: Offset in bytes within the bytearray the table resides
        """
        # Get initial values to calculate the size of the table
        (nbucket, nchain) = unpack('II', data[offset:offset+8])
        ent_size = 8 + nbucket * 4 + nchain * 4
        struct = f"II{nbucket}I{nchain}I"
        super().__init__(data, 0, offset, ent_size, struct)

        # Add the table values
        self._bucket = self._create_numeric_value(data, nbucket, offset + 8, 'I', 4)
        self._chain = self._create_numeric_value(data, nchain, offset + 8 + (nbucket * 4), 'I', 4)


class GnuHashTable(StructEntity):
    """ GNU Hash Table
    uint32_t    nbucket;            /* Number of buckets within the table */
    uint32_t    symoffset;          /* Offset within the symbol table of symbols the hash table applies to */
    uint32_t    bloom_size;         /* Size of the bloom structure */
    uint32_t    bloom_shift;        /* Number of bits to shift the has by within the bloom algorithm */
    uint64_t    bloom[bloom_size];  /* The bloom array */
    uint32_t    buckets[nbuckets];  /* Buckets containing an array of indexes of first symbols in the chain */
    uint32_t    chain[];            /* Contiguous collection of symbol hashes */
    """
    @property
    def nbucket(self):
        """ Gets or sets the number of buckets in the table """
        return self._get_value(0)

    @nbucket.setter
    def nbucket(self, value):
        self._set_value(0, value)

    @property
    def symoffset(self):
        """ Gets or sets the offset within the symbol table the hash table applies to """
        return self._get_value(1)

    @symoffset.setter
    def symoffset(self, value):
        self._set_value(1, value)

    @property
    def bloom_size(self):
        """ Gets or sets the number of bloom entries """
        return self._get_value(2)

    @bloom_size.setter
    def bloom_size(self, value):
        self._set_value(2, value)

    @property
    def bloom_shift(self):
        """ Gets or sets the bit-shift bloom value """
        return self._get_value(3)

    @bloom_shift.setter
    def bloom_shift(self, value):
        self._set_value(3, value)

    @property
    def bloom(self):
        """ Gets the bloom array """
        return self._bloom

    @property
    def bucket(self):
        """ Gets the list of bucket values """
        return self._bucket

    @property
    def chain(self):
        """ Gets the list of chain values """
        return self._chain

    def __init__(self, data, offset, ent_size):
        """ Instantiates a new HashTable at the offset given.

        :param data: Full bytearray data of the value
        :param offset: Offset in bytes within the bytearray the table resides
        :param ent_size: Size of the full hash table structure in bytes
        """
        # Get initial values to calculate the size of the table
        (nbucket, _, bloom_size) = unpack('III', data[offset:offset+12])
        init_size = (4*4) + (bloom_size*8) + (nbucket*4)  # Size without the chain
        nchain = int((ent_size - init_size) / 4)
        struct = f"IIII{bloom_size}Q{nbucket}I{nchain}I"
        super().__init__(data, 0, offset, ent_size, struct)

        # Add the table values
        self._bloom = self._create_numeric_value(data, bloom_size, offset + 16, 'Q', 8)
        self._bucket = self._create_numeric_value(data, nbucket, offset + 16 + (bloom_size*8), 'I', 4)
        self._chain = self._create_numeric_value(data, nchain, offset + 16 + (bloom_size*8) + (nbucket*4), 'I', 4)


class RelTableEntry(StructEntity):
    """ Relocation Table Entry
    Elf64_Addr      r_offset;       /* Location at which to apply the relocation action, the byte offset from
                                       the beginning of the section to the storage unit affected by the relocation */
    Elf64_Xword     r_info;         /* A RelInfo object which gives both the symbol table index with respect to which
                                       the relocation must be made, and the type of relocation to apply. */
    """
    @property
    def r_offset(self):
        """ Gets or sets the offset from the start of the object section to which relocation applies """
        return self._get_value(0)

    @r_offset.setter
    def r_offset(self, value):
        self._set_value(0, value)

    @property
    def r_info(self):
        """ Gets the r_info object containing the symbol table index and relocation type of the entry """
        return self._r_info

    def __init__(self, data, ent_idx, offset, ent_size=16, struct='QQ'):
        super().__init__(data, ent_idx, offset, ent_size, struct)
        self._r_info = RelInfo(data, 0, offset + (ent_idx * ent_size) + 8)
        self.symbol = None

    def update_symbol(self, symtab):
        """ Updates the symbol the relocation object points to as a Symbol object from the relevant symtab

        :param symtab: The symbol table pointed to by the sections sh_link property
        """
        if self.r_info.r_sym > 0:
            self.symbol = symtab[self.r_info.r_sym]

    def __str__(self):
        if self.symbol is not None:
            return f"{self.r_info.r_type.name} @ {hex(self.r_offset)}: {self.symbol.symbol_name}"
        else:
            return f"{self.r_info.r_type.name} @ {hex(self.r_offset)}"


class RelaTableEntry(RelTableEntry):
    """ Relocation Table Entry
    Similar to the RelTableEntry, however also includes an addend, which specifies a constant addend used to
    compute the value to be stored into the relocatable field.

    Elf64_Addr      r_offset;       /* Location at which to apply the relocation action, the byte offset from
                                       the beginning of the section to the storage unit affected by the relocation */
    Elf64_Xword     r_info;         /* A RelInfo object which gives both the symbol table index with respect to which
                                       the relocation must be made, and the type of relocation to apply. */
    Elf64_Sxword    r_addend;       /* Specifies a constant addend used to compute the value to be stored into the
                                       relocatable field */
    """
    @property
    def r_addend(self):
        """ Gets or sets the addend used to compute the value to be stored into the relocatable field """
        return self._get_value(2)

    @r_addend.setter
    def r_addend(self, value):
        self._set_value(2, value)

    def __init__(self, data, ent_idx, offset):
        super().__init__(data, ent_idx, offset, 24, 'QQQ')


class RelInfo(StructEntity):
    """ Contains information on a relocation object, including the symtab index and relocation type """
    @property
    def r_sym(self):
        """ Gets or sets the symbol table index with respect to which the relocation must be made """
        return self._get_value(0) >> 32

    @r_sym.setter
    def r_sym(self, value):
        self._set_value(0, value << 32 | self.r_type.value)

    @property
    def r_type(self):
        """ Gets or sets the type of relocation to apply """
        return RelocationType(self._get_value(0) & 0xffffffff)

    @r_type.setter
    def r_type(self, value):
        self._set_value(0, self.r_sym << 32 | value.value)

    def __init__(self, data, ent_idx, offset):
        """ Instantiates a new RelInfo object

        :param data: A bytearray containing the full data of the binary
        :param ent_idx: The index of the entity from the base of its parent structure
        :param offset: The offset of the parent structure
        """
        super().__init__(data, ent_idx, offset, 8, 'Q')


class NumericValue(StructEntity):
    """
    A NumericValue simply represents an numeric data value. This is a wrapper around values to enable getting/setting
    the value at the offset within a binary, taking into account the fact that data may have changed outside of
    the class since it was last read.

    This is used when the property using it doesn't contain a scalar value, but instead contains an arbitrary number
    of values as a list.
    """

    @property
    def val(self):
        return self._get_value(0)

    @val.setter
    def val(self, value):
        self._set_value(0, value)

    def __str__(self):
        return hex(self.val)
