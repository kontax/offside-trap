from struct import unpack

from elf.data import DynamicTableEntry, Note
from elf.enums import SectionType
from elf.helpers import parse_string_data, parse_header, repack
from elf.symbol import parse_symbols_data


def create_dynamic_table(full_data, data, offset):
    i = 0
    table = []
    struct = 'QQ'
    while i < len(data):
        d_tag, d_un = unpack(struct, data[i:i + 16])
        table.append(DynamicTableEntry(full_data, d_tag, d_un, offset + i, struct))
        i += 16

    return table


def parse_notes_data(data):
    notes = []
    # TODO: Extract bit size from ELF header to handle 32 bit binaries
    word_size = 4
    # Parse the data to extract the length
    i = 0
    while i < len(data):
        namesz = unpack('I', data[i:i+word_size])[0]
        i += word_size
        descsz = unpack('I', data[i:i+word_size])[0]
        i += word_size
        note_type = unpack('I', data[i:i+word_size])[0]
        i += word_size

        # Ensure sizes are aligned correctly
        name_pad = (word_size - namesz % word_size) % word_size
        desc_pad = (word_size - descsz % word_size) % word_size

        name = unpack(f"{namesz}s", data[i:i+namesz])[0].decode('utf-8').replace('\0', '')
        i += namesz + name_pad
        desc = unpack(f"{descsz}s", data[i:i+descsz])[0]
        i += descsz + desc_pad

        notes.append(Note(namesz, descsz, note_type, name, desc))

    return notes


class SectionFactory:
    @staticmethod
    def create_section(data, section_number, e_shoff, e_shentsize, header_names=None):
        hdr_struct = "IIQQQQIIQQ"
        section_header = parse_header(data, section_number, e_shentsize, e_shoff, hdr_struct)
        section_type = SectionType(section_header[1])
        section = Section(data, section_number, e_shoff, e_shentsize, header_names)
        if section_type == SectionType.SHT_DYNAMIC:
            return DynamicSection(data, section_number, e_shoff, e_shentsize, header_names)
        elif section_type == SectionType.SHT_DYNSYM:
            return SymbolTableSection(data, section_number, e_shoff, e_shentsize, header_names)
        elif section_type == SectionType.SHT_HASH:
            return HashSection(data, section_number, e_shoff, e_shentsize, header_names)
        elif section_type == SectionType.SHT_GNU_HASH:
            return GnuHashSection(data, section_number, e_shoff, e_shentsize, header_names)
        elif section_type == SectionType.SHT_NOTE:
            return NoteSection(data, section_number, e_shoff, e_shentsize, header_names)
        elif section_type == SectionType.SHT_REL:
            return section  # TODO: Modify
        elif section_type == SectionType.SHT_RELA:
            return section  # TODO: Modify
        elif section_type == SectionType.SHT_SYMTAB:
            return SymbolTableSection(data, section_number, e_shoff, e_shentsize, header_names)
        elif section_type == SectionType.SHT_STRTAB:
            return StringTableSection(data, section_number, e_shoff, e_shentsize, header_names)
        else:
            return Section(data, section_number, e_shoff, e_shentsize, header_names)


class Section:
    """ Section Header
    Elf64_Word      sh_name;        /* Section name */
    Elf64_Word      sh_type;        /* Section type */
    Elf64_Xword     sh_flags;       /* Section attributes */
    Elf64_Addr      sh_addr;        /* Virtual address in memory */
    Elf64_Off       sh_offset;      /* Offset in file */
    Elf64_Xword     sh_size;        /* Size of section */
    Elf64_Word      sh_link;        /* Link to other section */
    Elf64_Word      sh_info;        /* Miscellaneous information */
    Elf64_Xword     sh_addralign;   /* Address alignment boundary */
    Elf64_Xword     sh_entsize;     /* Size of entries, if section has table */
    """

    @property
    def header(self):
        """ Gets the tuple containing the values within the header of the entity """
        return (
            self._sh_name,
            self._sh_type.value,
            self._sh_flags,
            self._sh_addr,
            self._sh_offset,
            self._sh_size,
            self._sh_link,
            self._sh_info,
            self._sh_addralign,
            self._sh_entsize
        )

    @property
    def sh_name(self):
        """ Gets or sets the name of section """
        return self._sh_name

    @sh_name.setter
    def sh_name(self, value):
        self._sh_name = value
        self._repack_header()

    @property
    def sh_type(self):
        """ Gets or sets the type of section """
        return self._sh_type

    @sh_type.setter
    def sh_type(self, value):
        self._sh_type = value
        self._repack_header()

    @property
    def sh_flags(self):
        """ Gets or sets the RWX flags of the section """
        return self._sh_flags

    @sh_flags.setter
    def sh_flags(self, value):
        self._sh_flags = value
        self._repack_header()

    @property
    def sh_addr(self):
        """ Gets or sets the virtual address in memory of the section """
        return self._sh_addr

    @sh_addr.setter
    def sh_addr(self, value):
        self._sh_addr = value
        self._repack_header()

    @property
    def sh_offset(self):
        """ Gets or sets the offset in bytes within the file of the section """
        return self._sh_offset

    @sh_offset.setter
    def sh_offset(self, value):
        self._sh_offset = value
        self._repack_header()

    @property
    def sh_size(self):
        """ Gets or sets the size in bytes within the file of the section """
        return self._sh_size

    @sh_size.setter
    def sh_size(self, value):
        self._sh_size = value
        self._repack_header()

    @property
    def sh_link(self):
        """ Gets or sets the link to the next section if relevant """
        return self._sh_link

    @sh_link.setter
    def sh_link(self, value):
        self._sh_link = value
        self._repack_header()

    @property
    def sh_info(self):
        """ Gets or sets miscellaneous information about the section """
        return self._sh_info

    @sh_info.setter
    def sh_info(self, value):
        self._sh_info = value
        self._repack_header()

    @property
    def sh_addralign(self):
        """ Gets or sets the address alignment boundary of the section """
        return self._sh_addralign

    @sh_addralign.setter
    def sh_addralign(self, value):
        self._sh_addralign = value
        self._repack_header()

    @property
    def sh_entsize(self):
        """ Gets or sets the size of the entries if the section has a table """
        return self._sh_entsize

    @sh_entsize.setter
    def sh_entsize(self, value):
        self._sh_entsize = value
        self._repack_header()

    @property
    def symbols(self):
        """ Gets the collection of symbols that point to references within the section """
        return self._symbols

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        self._full_data = data
        self.hdr_struct = "IIQQQQIIQQ"
        self.e_shoff = e_shoff  # Section header offset
        self.e_shentsize = e_shentsize
        self.section_number = section_number
        self._symbols = []
        (
            self._sh_name,
            self._sh_type,
            self._sh_flags,
            self._sh_addr,
            self._sh_offset,
            self._sh_size,
            self._sh_link,
            self._sh_info,
            self._sh_addralign,
            self._sh_entsize
        ) = self._parse_header(data, section_number)

        # Get the name of the section
        if header_names is not None:
            self.section_name = parse_string_data(header_names.decode('utf-8'), self.sh_name)

        # Extract raw data
        self.data = data[self.sh_offset:self.sh_offset + self.sh_size]

    def load_symbols(self, symbols):
        """
        Parses a list of symbols and adds them to the local collection if they are contained within
        the address range of the current section.

        :param symbols: The full collection of symbols to check.
        """
        relevant_symbols = [x for x in symbols
                            if x.st_value >= self.sh_addr
                            and x.st_value + x.st_size <= self.sh_addr + self.sh_size]
        self._symbols.extend(relevant_symbols)

    def __str__(self):
        return f"{self.section_name} @ {hex(self.sh_offset)}"

    def _parse_header(self, data, section_number):
        header = parse_header(data, section_number, self.e_shentsize, self.e_shoff, self.hdr_struct)
        return (
            header[0],
            SectionType(header[1]),
            header[2],
            header[3],
            header[4],
            header[5],
            header[6],
            header[7],
            header[8],
            header[9],
        )

    def _repack_header(self):
        offset = self.e_shoff + (self.section_number * self.e_shentsize)
        repack(self._full_data, offset, self.e_shentsize, self.header, self.hdr_struct)


class DynamicSection(Section):
    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)

        self.dynamic_table = create_dynamic_table(self._full_data, self.data, self.sh_offset)


class NoteSection(Section):
    def __init__(self, data, segment_number, e_shoff, e_shentsize, header_names=None):
        super().__init__(data, segment_number, e_shoff, e_shentsize, header_names)
        self.notes = parse_notes_data(self.data)


class SymbolTableSection(Section):
    def __init__(self, data, segment_number, e_shoff, e_shentsize, header_names=None):
        super().__init__(data, segment_number, e_shoff, e_shentsize, header_names)
        self.symbol_table = parse_symbols_data(self._full_data, self.sh_offset, self.sh_size, self.sh_entsize, None)

    def populate_symbol_names(self, strtab):
        for symbol in self.symbol_table:
            symbol.populate_names(strtab)


class StringTableSection(Section):
    def __init__(self, data, segment_number, e_shoff, e_shentsize, header_names=None):
        super().__init__(data, segment_number, e_shoff, e_shentsize, header_names)
        self.strings = self.data.decode('utf-8').split('\0')
        

class HashSection(Section):
    def __init__(self, data, segment_number, e_shoff, e_shentsize, header_names=None):
        super().__init__(data, segment_number, e_shoff, e_shentsize, header_names)
        self.hash_table = self._get_hash_table(self.data)

    @staticmethod
    def _get_hash_table(data):
        buckets = []
        chain = []

        (nbucket, nchain) = unpack('II', data[0:8])

        start = 8
        buckets.extend(unpack('I'*nbucket, data[start:start + nbucket * 4]))

        start = start + (nbucket * 4)
        chain.extend(unpack('I'*nchain, data[start:start + nchain * 4]))

        hash_table = HashTable(nbucket, nchain, buckets, chain)

        return hash_table

    @staticmethod
    def hash(name):
        h = 0
        for n in name:
            c = ord(n)
            h = (h << 4) + c
            g = h & 0xf0000000
            if g > 0:
                h ^= g >> 24
            h &= ~g
        return hex(h)


class GnuHashSection(Section):
    def __init__(self, data, segment_number, e_shoff, e_shentsize, header_names=None):
        super().__init__(data, segment_number, e_shoff, e_shentsize, header_names)
        self.hash_table = self._get_hash_table(self.data)

    @staticmethod
    def _get_hash_table(data):
        bloom = []
        buckets = []
        chain = []

        (nbucket, symoffset, bloom_size, bloom_shift) = unpack('IIII', data[0:16])

        start = 16
        bloom.extend(unpack('Q'*bloom_size, data[start:start + bloom_size * 8]))

        start = start + bloom_size * 8
        buckets.extend(unpack('I'*nbucket, data[start:start + nbucket * 4]))

        start = start + nbucket * 4
        nchain = (len(data) - start) / 4
        nchain = int(nchain)
        chain.extend(unpack('I'*nchain, data[start:start + nchain * 4]))

        return GnuHashTable(nbucket, symoffset, bloom_size, bloom_shift, bloom, buckets, chain)

    @staticmethod
    def hash(name):
        h = 5381
        for n in name:
            h = (h << 5) + h + ord(n)

        return h & 0xffffffff


class HashTable:
    def __init__(self, nbucket, nchain, buckets, chains):
        self.nbucket = nbucket
        self.nchain = nchain
        self.buckets = buckets
        self.chains = chains


class GnuHashTable:
    def __init__(self, nbucket, symoffset, bloom_size, bloom_shift, bloom, buckets, chain):
        self.nbucket = nbucket
        self.symoffset = symoffset
        self.bloom_size = bloom_size
        self.bloom_shift = bloom_shift
        self.bloom = bloom
        self.buckets = buckets
        self.chain = chain
