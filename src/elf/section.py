from struct import unpack

from elf.data import DynamicTableEntry, Note
from elf.enums import *
from elf.helpers import parse_string_data, parse_header, repack
from elf.symbol import parse_symbols_data


def create_dynamic_table(full_data, data, offset):
    """ Creates a dynamic table containing references to symbols within the dynamic strtab.
    :return: A list of DynamicTableEntry objects
    """
    i = 0
    table = []
    struct = 'QQ'
    while i < len(data):
        d_tag, d_un = unpack(struct, data[i:i + 16])
        table.append(DynamicTableEntry(full_data, d_tag, d_un, offset + i, struct))
        i += 16

    return table


def parse_notes_data(data):
    """ Parses the section data to extract a list of notes from within the binary
    :return: A list of Note objects
    """
    notes = []
    # TODO: Extract bit size from ELF header to handle 32 bit binaries
    word_size = 4
    # Parse the data to extract the length
    i = 0
    while i < len(data):
        namesz = unpack('I', data[i:i + word_size])[0]
        i += word_size
        descsz = unpack('I', data[i:i + word_size])[0]
        i += word_size
        note_type = unpack('I', data[i:i + word_size])[0]
        i += word_size

        # Ensure sizes are aligned correctly
        name_pad = (word_size - namesz % word_size) % word_size
        desc_pad = (word_size - descsz % word_size) % word_size

        name = unpack(f"{namesz}s", data[i:i + namesz])[0].decode('utf-8').replace('\0', '')
        i += namesz + name_pad
        desc = unpack(f"{descsz}s", data[i:i + descsz])[0]
        i += descsz + desc_pad

        notes.append(Note(namesz, descsz, note_type, name, desc))

    return notes


class SectionFactory:
    @staticmethod
    def create_section(data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Creates a new section dependent on the value of the section type.

        :param data: The bytearray representation of the binary
        :param section_number: The index of the section within the section table
        :param e_shoff: The offset in bytes of the section header from the start of the binary
        :param e_shentsize: The size in bytes of each entry within the section header table
        :param header_names: The list of names given to sections if available
        :return: A Section or subclass
        """
        hdr_struct = "IIQQQQIIQQ"
        section_header = parse_header(data, section_number, e_shentsize, e_shoff, hdr_struct)
        section_type = SectionType(section_header[1])
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
        elif section_type == SectionType.SHT_PROGBITS:
            return CodeSection(data, section_number, e_shoff, e_shentsize, header_names)
        elif section_type == SectionType.SHT_REL:
            return RelocationSection(data, section_number, e_shoff, e_shentsize, header_names)
        elif section_type == SectionType.SHT_RELA:
            return RelocationSection(data, section_number, e_shoff, e_shentsize, header_names)
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

    @property
    def linked_section(self):
        """ Gets a section refereneced by sh_link if one is present """
        return self._linked_section

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new Section object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        self._full_data = data
        self.hdr_struct = "IIQQQQIIQQ"
        self.e_shoff = e_shoff  # Section header offset
        self.e_shentsize = e_shentsize
        self.section_number = section_number
        self._linked_section = None
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

    def set_linked_section(self, sections):
        """ Sets the linked_section property to whatever index is referenced in the sh_link property.

        :param sections: A list of Section objects within the ELF
        """
        self._linked_section = sections[self.sh_link] if self.sh_link > 0 else None

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
    """ The dynamic section contains references to a string table holding the list of symbols the binary loads
    via the dynamic loader. """

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new DynamicSection object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)

        self.dynamic_table = create_dynamic_table(self._full_data, self.data, self.sh_offset)


class NoteSection(Section):
    """ Contains special information that other programs will check for conformance, compatibility, etc. """

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new NoteSection object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)
        self.notes = parse_notes_data(self.data)


class SymbolTableSection(Section):
    """ Contains a collection of symbols used by the binary. """

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new SymbolTableSection object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)
        self.symbol_table = parse_symbols_data(self._full_data, self.sh_offset, self.sh_size, self.sh_entsize, None)

    def populate_symbol_names(self, strtab):
        for symbol in self.symbol_table:
            symbol.populate_names(strtab)


class StringTableSection(Section):
    """ Contains a list of strings usually referenced by a symbol table section. """

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new StringTableSection object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)
        self.strings = self.data.decode('utf-8').split('\0')


class HashSection(Section):
    """ A representation of the SYSV hashtable, which has mostly been replaced by the newer GNU hash table for
    performance reasons. """

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new HashSection object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)
        self.hash_table = self._get_hash_table(self.data)

    @staticmethod
    def _get_hash_table(data):
        """ Creates a HashTable object given the bytearray representation of it.

        :param data: A bytearray representation of the hashtable
        :return: A HashTable object.
        """
        buckets = []
        chain = []

        (nbucket, nchain) = unpack('II', data[0:8])

        start = 8
        buckets.extend(unpack('I' * nbucket, data[start:start + nbucket * 4]))

        start = start + (nbucket * 4)
        chain.extend(unpack('I' * nchain, data[start:start + nchain * 4]))

        hash_table = HashTable(nbucket, nchain, buckets, chain)

        return hash_table

    @staticmethod
    def hash(name):
        """ Hash algorithm used for the SYSV hashing method.

        :param name: The name of the symbol to hash
        :return: A 32 bit hash value of the symbol used
        """
        h = 0
        for n in name:
            c = ord(n)
            h = (h << 4) + c
            g = h & 0xf0000000
            if g > 0:
                h ^= g >> 24
            h &= ~g
        return h

    def find(self, name):
        """ Uses the SYSV hash lookup algorithm to search for a symbol name within the symbol table from the linked
        section found by sh_link.

        :param name: The name of the symbol to search for
        :return: A Symbol object if the symbol is found, otherwise None
        """
        if name is None:
            return None

        symtab = self.linked_section.symbol_table
        hashed = self.hash(name)
        bucket = hashed % self.hash_table.nbucket
        ix = self.hash_table.bucket[bucket]
        while name != symtab[ix].symbol_name and self.hash_table.chain[ix] != 0:
            ix = self.hash_table.chain[ix]

        return None if name != symtab[ix].symbol_name and self.hash_table.chain[ix] == 0 else symtab[ix]


class GnuHashSection(Section):
    """ A representation of the GNU hash table, which has mostly superseded the original SYSV hash table by implementing
    a bloom lookup for performance reasons. """

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new GnuHashSection object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)
        self.hash_table = self._get_hash_table(self.data)

    @staticmethod
    def _get_hash_table(data):
        """ Creates a GnuHashTable object given the bytearray representation of it.

        :param data: A bytearray representation of the hashtable
        :return: A GnuHashTable object.
        """
        bloom = []
        buckets = []
        chain = []

        (nbucket, symoffset, bloom_size, bloom_shift) = unpack('IIII', data[0:16])

        start = 16
        bloom.extend(unpack('Q' * bloom_size, data[start:start + bloom_size * 8]))

        start = start + bloom_size * 8
        buckets.extend(unpack('I' * nbucket, data[start:start + nbucket * 4]))

        start = start + nbucket * 4
        nchain = (len(data) - start) / 4
        nchain = int(nchain)
        chain.extend(unpack('I' * nchain, data[start:start + nchain * 4]))

        return GnuHashTable(nbucket, symoffset, bloom_size, bloom_shift, bloom, buckets, chain)

    @staticmethod
    def hash(name):
        """ Hash algorithm used for the GNU hashing method.

        :param name: The name of the symbol to hash
        :return: A 32 bit hash value of the symbol used
        """
        h = 5381
        for n in name:
            h = (h << 5) + h + ord(n)

        return h & 0xffffffff

    def find(self, name):
        """ Uses the GNU hash lookup algorithm, including a bloom filter, to search for a symbol name within
        the symbol table found via the sh_link property.

        :param name: The name of the symbol to search for
        :return: A Symbol object if the symbol is found, otherwise None
        """
        if name is None:
            return "None"

        elf_class = 64

        ht = self.hash_table
        hashed = self.hash(name)
        symtab = self.linked_section.symbol_table

        # Use the bloom algorithm to check if the symbol could be within the table
        bloom_ix = int((hashed / 64) % ht.bloom_size)
        bloom_check = ht.bloom[bloom_ix]
        if not (bloom_check >> (hashed % 64)) & (bloom_check >> ((hashed >> ht.bloom_shift) % elf_class)) & 1:
            return None

        # Perform the index search
        ix = ht.bucket[hashed % ht.nbucket]
        if ix < ht.symoffset:
            return None

        # Loop through the chain
        while True:
            hash_comp = ht.chain[ix - ht.symoffset]

            # The last bit is used to signify the end of the chain
            if (hash_comp | 1) == (hashed | 1) and name == symtab[ix].symbol_name:
                return symtab[ix]

            # Finish here if the last bit is set
            if hash_comp & 1:
                break

            ix += 1

        return None


class CodeSection(Section):
    """ Contains executable data, such as .text or .plt """

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new CodeSection object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)
        self.assembly = None

    def _get_assembly(self):
        print("Not impelemented yet")
        if self.assembly is None:
            return None


class RelocationSection(Section):
    """ Contains details on connecting symbolic references with symbolic definitions """

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new RelocationSection object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)
        self.relocation_table = self._get_rel_table()

    def set_linked_section(self, sections):
        """ Sets the linked_section property from the sh_link header value

        :param sections: The full collection of sections within the binary
        """
        super().set_linked_section(sections)
        if self.linked_section is None:
            return

        # Link each symbol within the relocation table to a symbol in the symtab
        for entry in self.relocation_table:
            entry.update_symbol(self.linked_section.symbol_table)

    def _get_rel_table(self):
        num_entries = int(self.sh_size / self.sh_entsize)

        table = []
        for i in range(num_entries):
            offset = i * self.sh_entsize
            if self.sh_type == SectionType.SHT_REL:
                (r_offset, r_info) = unpack("QQ", self.data[offset:offset + self.sh_entsize])
                table.append(RelTableEntry(r_offset, r_info))
            elif self.sh_type == SectionType.SHT_RELA:
                (r_offset, r_info, r_addend) = unpack("QQQ", self.data[offset:offset + self.sh_entsize])
                table.append(RelaTableEntry(r_offset, r_info, r_addend))
            else:
                # Should not get here
                raise ValueError(f"Section type {self.sh_type} is invalid")

        return table


class HashTable:
    """ The object containing details about the SYSV hash table """

    def __init__(self, nbucket, nchain, bucket, chain):
        """ Instantiates a new HashTable

        :param nbucket: The number of buckets within the table
        :param nchain: The number of chains within the table
        :param bucket: The bucket
        :param chain: The chain
        """
        self.nbucket = nbucket
        self.nchain = nchain
        self.bucket = bucket
        self.chain = chain


class GnuHashTable:
    """ The object containing details about the GNU hash table """

    def __init__(self, nbucket, symoffset, bloom_size, bloom_shift, bloom, bucket, chain):
        """ Instantiate a new GnuHashTable object

        :param nbucket: The number of buckets within the table
        :param symoffset: The offset within the symbol table that the hash table points to
        :param bloom_size: The size of the bloom filter
        :param bloom_shift: The bloom shift
        :param bloom: The bloom value
        :param bucket: The bucket
        :param chain: The chain
        """
        self.nbucket = nbucket
        self.symoffset = symoffset
        self.bloom_size = bloom_size
        self.bloom_shift = bloom_shift
        self.bloom = bloom
        self.bucket = bucket
        self.chain = chain


class RelTableEntry:
    """ An entry into the relocation table, containing details about a single symbol relocation """

    def __init__(self, r_offset, r_info):
        """ Instantiates a new RelTableEntry

        :param r_offset: The location at which to apply the relocation action, the byte offset from the beginning of
        the section to the storage unit affected by the relocation
        :param r_info: A RelInfo object which gives both the symbol table index with respect to which the relocation
        must be made, and the type of relocation to apply.
        """
        self.r_offset = r_offset
        self.r_info = RelInfo(r_info)
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
    """ Similar to the RelTableEntry, however also includes an addend, which specifies a constant addend used to
    compute the value to be stored into the relocatable field. """

    def __init__(self, r_offset, r_info, r_addend):
        """ Instantiates a new RelaTableEntry

        :param r_offset: The location at which to apply the relocation action, the byte offset from the beginning of
        the section to the storage unit affected by the relocation
        :param r_info: A RelInfo object which gives both the symbol table index with respect to which the relocation
        must be made, and the type of relocation to apply.
        :param r_addend: Specifies a constant addend used to compute the value to be stored into the relocatable field
        """
        super().__init__(r_offset, r_info)
        self.r_addend = r_addend


class RelInfo:
    """ Contains information on a relocation object, including the symtab index and relocation type """

    def __init__(self, r_info):
        """ Instantiates a new RelInfo object

        :param r_info: A RelInfo object which gives both the symbol table index with respect to which the relocation
        must be made, and the type of relocation to apply.
        """
        self.r_sym = r_info >> 32
        self.r_type = RelocationType(r_info & 0xffffffff)
