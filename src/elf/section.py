from elf.data import *
from elf.enums import *
from elf.helpers import parse_string_data, parse_struct, _check_range_overlaps
from elf.symbol import parse_symbols_data


def create_dynamic_table(full_data, data, offset):
    """ Creates a dynamic table containing references to symbols within the dynamic strtab.
    :return: A list of DynamicTableEntry objects
    """
    i = 0
    table = []
    while i < len(data):
        table.append(DynamicTableEntry(full_data, int(i / 16), offset))
        i += 16

    return table


def parse_notes_data(full_data, data, offset):
    """ Parses the section data to extract a list of notes from within the binary
    :return: A list of Note objects
    """
    notes = []
    # TODO: Extract bit size from ELF header to handle 32 bit binaries
    word_size = 4
    # Parse the data to extract the length
    i = 0
    while i < len(data):
        (namesz, descsz, note_type) = unpack('III', data[i:i+12])

        # Ensure sizes are aligned correctly
        name_pad = (word_size - namesz % word_size) % word_size
        desc_pad = (word_size - descsz % word_size) % word_size

        # Create the note
        notes.append(Note(full_data, offset))

        # Shift by the amount of bytes within the note section
        i += 12 + namesz + name_pad + descsz + desc_pad
        offset += i

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
        section_header = parse_struct(data, section_number, e_shoff, e_shentsize, hdr_struct)
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


class SectionHeader(StructEntity):
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
    def sh_name(self):
        """ Gets or sets the name of section """
        return self._get_value(0)

    @sh_name.setter
    def sh_name(self, value):
        self._set_value(0, value)

    @property
    def sh_type(self):
        """ Gets or sets the type of section """
        return SectionType(self._get_value(1))

    @sh_type.setter
    def sh_type(self, value):
        self._set_value(1, value.value)

    @property
    def sh_flags(self):
        """ Gets or sets the RWX flags of the section """
        return self._get_value(2)

    @sh_flags.setter
    def sh_flags(self, value):
        self._set_value(2, value)

    @property
    def sh_addr(self):
        """ Gets or sets the virtual address in memory of the section """
        return self._get_value(3)

    @sh_addr.setter
    def sh_addr(self, value):
        self._set_value(3, value)

    @property
    def sh_offset(self):
        """ Gets or sets the offset in bytes within the file of the section """
        return self._get_value(4)

    @sh_offset.setter
    def sh_offset(self, value):
        self._set_value(4, value)

    @property
    def sh_size(self):
        """ Gets or sets the size in bytes within the file of the section """
        return self._get_value(5)

    @sh_size.setter
    def sh_size(self, value):
        self._set_value(5, value)

    @property
    def sh_link(self):
        """ Gets or sets the link to the next section if relevant """
        return self._get_value(6)

    @sh_link.setter
    def sh_link(self, value):
        self._set_value(6, value)

    @property
    def sh_info(self):
        """ Gets or sets miscellaneous information about the section """
        return self._get_value(7)

    @sh_info.setter
    def sh_info(self, value):
        self._set_value(7, value)

    @property
    def sh_addralign(self):
        """ Gets or sets the address alignment boundary of the section """
        return self._get_value(8)

    @sh_addralign.setter
    def sh_addralign(self, value):
        self._set_value(8, value)

    @property
    def sh_entsize(self):
        """ Gets or sets the size of the entries if the section has a table """
        return self._get_value(9)

    @sh_entsize.setter
    def sh_entsize(self, value):
        self._set_value(9, value)

    def __init__(self, data, section_number, e_shoff, e_shentsize):
        """ Instantiates a new Section object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        """
        hdr_struct = "IIQQQQIIQQ"
        super().__init__(data, section_number, e_shoff, e_shentsize, hdr_struct)


class Section:

    @property
    def symbols(self):
        """ Gets the collection of symbols that point to references within the section """
        return self._symbols

    @property
    def linked_section(self):
        """ Gets a section refereneced by sh_link if one is present """
        return self._linked_section

    @property
    def data(self):
        return self._data

    @property
    def live_data(self):
        start = self.header.sh_offset
        end = self.header.sh_offset + self.header.sh_size
        return self._full_data[start:end]

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new Section object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        self._full_data = data
        self._linked_section = None
        self._symbols = []

        self.header = SectionHeader(data, section_number, e_shoff, e_shentsize)

        # Get the name of the section
        if header_names is not None:
            self.section_name = parse_string_data(header_names.decode('utf-8'), self.header.sh_name)

        # Set the current data value
        start = self.header.sh_offset
        end = self.header.sh_offset + self.header.sh_size
        self._data = self._full_data[start:end]

    def __str__(self):
        return f"{self.section_name} @ {hex(self.header.sh_offset)}"

    def shift(self, start_offset, end_offset, shift_by, virtual_base):
        hdr = self.header
        overlap = _check_range_overlaps(start_offset, end_offset, hdr.sh_offset, hdr.sh_offset + hdr.sh_size)
        if overlap is None:
            return

        # Move the start only if it's after the start offset
        if overlap == Overlap.RIGHT or overlap == Overlap.INNER:
            hdr.sh_offset += shift_by
            hdr.sh_addr += shift_by

            # Ensure the data still matches, and update the data snapshot
            assert (self.data == self.live_data)

        # Otherwise increase the size
        if overlap == Overlap.LEFT or overlap == Overlap.OVER:
            hdr.sh_size += shift_by

            # Ensure the start and end values match what they did previously, and update the snapshot
            assert (self.data[:shift_by] == self.live_data[:shift_by])
            assert (self.data[-shift_by:] == self.live_data[-shift_by:])

    def load_symbols(self, symbols):
        """
        Parses a list of symbols and adds them to the local collection if they are contained within
        the address range of the current section.

        :param symbols: The full collection of symbols to check.
        """
        relevant_symbols = [x for x in symbols
                            if x.header.st_value >= self.header.sh_addr
                            and x.header.st_value + x.header.st_size <= self.header.sh_addr + self.header.sh_size]
        self._symbols.extend(relevant_symbols)

    def set_linked_section(self, sections):
        """ Sets the linked_section property to whatever index is referenced in the sh_link property.

        :param sections: A list of Section objects within the ELF
        """
        self._linked_section = sections[self.header.sh_link] if self.header.sh_link > 0 else None


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

        self.dynamic_table = create_dynamic_table(self._full_data, self.data, self.header.sh_offset)

    def shift(self, start_offset, end_offset, shift_by, virtual_base):
        super().shift(start_offset, end_offset, shift_by, virtual_base)
        self.dynamic_table = create_dynamic_table(self._full_data, self.data, self.header.sh_offset)
        for entry in self.dynamic_table:
            entry.shift(start_offset, end_offset, shift_by, virtual_base)


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
        self.notes = parse_notes_data(self._full_data, self.data, self.header.sh_offset)

    def shift(self, start_offset, end_offset, shift_by, virtual_base):
        super().shift(start_offset, end_offset, shift_by, virtual_base)
        self.notes = parse_notes_data(self._full_data, self.data, self.header.sh_offset)


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
        self.symbol_table = parse_symbols_data(
            self._full_data, self.header.sh_offset, self.header.sh_size, self.header.sh_entsize, None)

    def populate_symbol_names(self):
        for symbol in self.symbol_table:
            symbol.populate_names(self.linked_section)

    def shift(self, start_offset, end_offset, shift_by, virtual_base):
        super().shift(start_offset, end_offset, shift_by, virtual_base)
        self.symbol_table = parse_symbols_data(
            self._full_data, self.header.sh_offset, self.header.sh_size, self.header.sh_entsize, None)

        for entry in self.symbol_table:
            entry.shift(start_offset, end_offset, shift_by, virtual_base)

        self.populate_symbol_names()


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
        self.hash_table = HashTable(data, self.header.sh_offset)

    def shift(self, start_offset, end_offset, shift_by, virtual_base):
        super().shift(start_offset, end_offset, shift_by, virtual_base)
        self.hash_table = HashTable(self._full_data, self.header.sh_offset)

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
        ix = self.hash_table.bucket[bucket].val
        while name != symtab[ix].symbol_name and self.hash_table.chain[ix].val != 0:
            ix = self.hash_table.chain[ix].val

        return None if name != symtab[ix].symbol_name and self.hash_table.chain[ix].val == 0 else symtab[ix]


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
        self.hash_table = GnuHashTable(data, self.header.sh_offset, self.header.sh_size)

    def shift(self, start_offset, end_offset, shift_by, virtual_base):
        super().shift(start_offset, end_offset, shift_by, virtual_base)
        self.hash_table = GnuHashTable(self._full_data, self.header.sh_offset, self.header.sh_size)

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
        bloom_check = ht.bloom[bloom_ix].val
        if not (bloom_check >> (hashed % 64)) & (bloom_check >> ((hashed >> ht.bloom_shift) % elf_class)) & 1:
            return None

        # Perform the index search
        ix = ht.bucket[hashed % ht.nbucket].val
        if ix < ht.symoffset:
            return None

        # Loop through the chain
        while True:
            hash_comp = ht.chain[ix - ht.symoffset].val

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

    @property
    def relocation_table(self):
        """ Gets the relocation table """
        return self._relocation_table

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        """ Instantiates a new RelocationSection object

        :param data: The full bytearray containing ELF data
        :param section_number: The index of the section within the ELF section list
        :param e_shoff: The offset of the section header within the file in bytes
        :param e_shentsize: The entity size of each section header entry in bytes
        :param header_names: The list of names given to sections if available
        """
        super().__init__(data, section_number, e_shoff, e_shentsize, header_names)
        self._relocation_table = self._get_rel_table()

    def shift(self, start_offset, end_offset, shift_by, virtual_base):
        super().shift(start_offset, end_offset, shift_by, virtual_base)
        self._relocation_table = self._get_rel_table()

        for entry in self._relocation_table:
            entry.shift(start_offset, end_offset, shift_by, virtual_base)
            if self.linked_section is not None:
                entry.update_symbol(self.linked_section.symbol_table)

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
        num_entries = int(self.header.sh_size / self.header.sh_entsize)

        table = []
        for i in range(num_entries):
            if self.header.sh_type == SectionType.SHT_REL:
                table.append(RelTableEntry(self._full_data, i, self.header.sh_offset))
            elif self.header.sh_type == SectionType.SHT_RELA:
                table.append(RelaTableEntry(self._full_data, i, self.header.sh_offset))
            else:
                # Should not get here
                raise ValueError(f"Section type {self.header.sh_type} is invalid")

        return table
