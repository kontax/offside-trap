from struct import pack

import r2pipe

from elf.data import StructEntity
from elf.enums import *
from elf.section import Section, SectionFactory, SymbolTableSection
from elf.segment import Segment, SegmentFactory

"""
ELF Specification: http://ftp.openwatcom.org/devel/docs/elf-64-gen.pdf
"""


class ELFIdent(StructEntity):
    """ e_ident containing identification details of the ELF file """

    @property
    def el_mag(self):
        """ Gets or sets the ELF file magic string """
        return self._get_value(0)

    @el_mag.setter
    def el_mag(self, value):
        self._set_value(0, value)

    @property
    def el_class(self):
        """ Gets or sets the file class """
        return ELFClass(self._get_value(1))

    @el_class.setter
    def el_class(self, value):
        self._set_value(1, value.value)

    @property
    def el_data(self):
        """ Gets or sets the data encoding type """
        return ELFData(self._get_value(2))

    @el_data.setter
    def el_data(self, value):
        self._set_value(2, value.value)

    @property
    def el_version(self):
        """ Gets or sets the ELF file version """
        return self._get_value(3)

    @el_version.setter
    def el_version(self, value):
        self._set_value(3, value)

    @property
    def el_osabi(self):
        """ Gets or sets the OS/ABI type """
        return ELFOSABI(self._get_value(4))

    @el_osabi.setter
    def el_osabi(self, value):
        self._set_value(4, value.value)

    @property
    def el_abiversion(self):
        """ Gets or sets the ABI version """
        return self._get_value(5)

    @el_abiversion.setter
    def el_abiversion(self, value):
        self._set_value(5, value)

    @property
    def el_pad(self):
        """ Gets the padding value """
        return self._get_value(6)

    @property
    def el_nident(self):
        """ Gets or sets the size of the e_ident struct """
        return self._get_value(7)

    @el_nident.setter
    def el_nident(self, value):
        self._set_value(7, value)

    def __init__(self, data):
        hdr_struct = "4sbbbbb6sb"
        super().__init__(data, 0, 0, 16, hdr_struct)
        assert (self.el_mag == b"\x7fELF")


class ELFHeader(StructEntity):
    """ File Header
    unsigned char   e_ident[16];    /* ELF identification */
    Elf64_Half      e_type;         /* Object file type */
    Elf64_Half      e_machine;      /* Machine type */
    Elf64_Word      e_version;      /* Object file version */
    Elf64_Addr      e_entry;        /* Entry point address */
    Elf64_Off       e_phoff;        /* Program header offset */
    Elf64_Off       e_shoff;        /* Section header offset */
    Elf64_Word      e_flags;        /* Processor-specific flags */
    Elf64_Half      e_ehsize;       /* ELF header size */
    Elf64_Half      e_phentsize;    /* Size of program header entry */
    Elf64_Half      e_phnum;        /* Number of program header entries */
    Elf64_Half      e_shentsize;    /* Size of section header entry */
    Elf64_Half      e_shnum;        /* Number of section header entries */
    Elf64_Half      e_shstrndx;     /* Section name string table index */
    """

    @property
    def elf_file(self):
        """ Gets a reference to the elf file object """
        return self._elf_file

    @property
    def e_ident(self):
        """ Gets values from the e_ident struct """
        return self._e_ident

    @property
    def e_type(self):
        """ Gets or sets the object file type of the binary """
        return ProgramType(self._get_value(1))

    @e_type.setter
    def e_type(self, value):
        self._set_value(1, value.value)

    @property
    def e_machine(self):
        """ Gets or sets the processor the binary runs on """
        return ELFMachine(self._get_value(2))

    @e_machine.setter
    def e_machine(self, value):
        self._set_value(2, value.value)

    @property
    def e_version(self):
        """ Gets or sets the ABI version """
        return self._get_value(3)

    @e_version.setter
    def e_version(self, value):
        self._set_value(3, value)

    @property
    def e_entry(self):
        """ Gets or sets the entry point of the program """
        return self._get_value(4)

    @e_entry.setter
    def e_entry(self, value):
        self._set_value(4, value)

    @property
    def e_phoff(self):
        """ Gets or sets the program header offset """
        return self._get_value(5)

    @e_phoff.setter
    def e_phoff(self, value):
        for seg in self.elf_file.segments:
            seg.header.e_phoff = value
        self._set_value(5, value)

    @property
    def e_shoff(self):
        """ Gets or sets the section header offset """
        return self._get_value(6)

    @e_shoff.setter
    def e_shoff(self, value):
        for sec in self.elf_file.sections:
            sec.header.e_shoff = value
        self._set_value(6, value)

    @property
    def e_flags(self):
        """ Gets processory-specific flags """
        return self._get_value(7)

    @property
    def e_ehsize(self):
        """ Gets the size of the ELF header in bytes """
        return self._get_value(8)

    @property
    def e_phentsize(self):
        """ Gets the size of each entry in the program header table """
        return self._get_value(9)

    @property
    def e_phnum(self):
        """ Gets or sets the number of entries in the program header """
        return self._get_value(10)

    @e_phnum.setter
    def e_phnum(self, value):
        self._set_value(10, value)

    @property
    def e_shentsize(self):
        """ Gets the size of each entry in the section header table """
        return self._get_value(11)

    @property
    def e_shnum(self):
        """ Gets or sets the number of entries in the section header """
        return self._get_value(12)

    @e_shnum.setter
    def e_shnum(self, value):
        self._set_value(12, value)

    @property
    def e_shstrndx(self):
        """ Gets or sets the index of the section name string table """
        return self._get_value(13)

    @e_shstrndx.setter
    def e_shstrndx(self, value):
        self._set_value(13, value)

    def __init__(self, data, elf_file):
        self._elf_file = elf_file
        hdr_struct = "16sHHIQQQIHHHHHH"
        super().__init__(data, 0, 0, 64, hdr_struct)
        self._e_ident = ELFIdent(data)


class ELF:

    @property
    def virtual_base(self):
        """ Gets the virtual base of the binary (eg. 0x4000000 if no-pie) """
        return self._virtual_base

    @property
    def linking_method(self):
        """ Gets how the ELF has been linked - dynamically or statically """
        return self._linking_method

    def __init__(self, file_path):
        data = open(file_path, 'rb').read()
        self.r2 = r2pipe.open(file_path)
        self.data = bytearray(data)
        self._full_data = self.data
        self.header = ELFHeader(self.data, self)
        self.segments = []
        self.sections = []
        self.symbols = []
        hdr = self.header

        # Pull the data containing the segment names initially
        shstrtab_data = Section(self.data, hdr.e_shstrndx, hdr.e_shoff, hdr.e_shentsize).data

        # Extract the Segments
        for i in range(hdr.e_phnum):
            self.segments.append(SegmentFactory.create_segment(self.data, i, hdr.e_phoff, hdr.e_phentsize))

        # Extract the Sections
        for i in range(hdr.e_shnum):
            section = SectionFactory.create_section(self.data, i, hdr.e_shoff, hdr.e_shentsize, shstrtab_data)
            self.sections.append(section)

        # Associate each section with the segment it's contained within
        for s in self.segments:
            s.load_sections(self.sections)

        # Whether the ELF is statically or dynamically linked
        self._linking_method = ELFLinkingMethod(len([x for x in self.sections if x.section_name == '.interp']))

        # Associate each symbol with the section it's contained within
        for s in self.sections:
            s.load_symbols(self.symbols)
            s.set_linked_section(self.sections)

        for symtab in [s for s in self.sections if type(s) is SymbolTableSection]:
            symtab.populate_symbol_names()
            self.symbols.extend(symtab.symbol_table)

        self._virtual_base = min(x.header.p_vaddr for x in self.segments if x.header.p_type == ProgramType.PT_LOAD)

    def list_functions(self):
        """
        Lists all functions and addresses within the text section fo the binary, using radare2 if it is available on
        the system, otherwise using the symbol table. If neither of those options  are available, the command fails
        as trying to manually extract functions is too error prone.

        :return: A collection of Function objects tuples within the text section and their addresses
        """

        # When symbols are available
        text = self.get_section('.text')

        if len(self.symbols) > 0:
            func_symbols = [Function(fn.symbol_name, fn.header.st_value, fn.header.st_size)
                            for fn in text.symbols
                            if fn.header.st_info.st_type == SymbolType.STT_FUNC]  # All functions
            return func_symbols

        else:
            # Analyse the functions using radare
            try:
                self.r2.cmd('aaa')
                functions = self.r2.cmdJ('aflj')
                return [Function(x.name, x.offset, x.size) for x in functions]

            # If r2 is not on the system, go for the less accurate method of searching the symbols, or call instructions
            except FileNotFoundError:
                raise FileNotFoundError("Radare2 was not found, and the binary is stripped. Cannot extract functions")

    def get_section(self, name):
        """
        Gets a section with the name specified. If more than one section have the name, an error is thrown.

        :param name: The name of the section to return
        :return: A Section object with the name specified
        """
        sections = [x for x in self.sections if x.section_name == name]
        assert (len(sections) <= 1)
        if len(sections) == 0:
            return None
        return sections[0]

    def get_data_segment(self, start_addr, end_addr):
        """
        Extracts a segment of data as a bytearray.

        :param start_addr: The offset in bytes wtihin the binary where the data to be extracted is found
        :param end_addr: The end address in bytes of the data
        :return: A bytearray containing the data
        """
        return self.data[start_addr:end_addr]

    def append_loadable_segment_3(self, size):
        """
        Appends a new segment of the size specified, modifying any relevant pointers required.

        Due to issues with modifying the program header, this function clobbers the NOTE segment/sections which reside
        after the program header or interp section. If that segment isn't a NOTE segment, issues will occur when
        running the binary.

        :param size: The minimum size to make the segment given required alignments
        :return: A new segment from within the ELF file
        """

        self._shift_interp()
        hdr = self.header

        # Create a new segment
        new_segment = self._create_new_segment(size)
        self.segments.append(new_segment)

        # Add header entry to end of header section
        hdr.e_phnum += 1

        return new_segment

    def _shift_interp(self):
        """
        Shifts the INTERP section/segment/symbol in order to make room for a new header section. This overwrites
        any data after this section, which is hopefully unused.
        """
        hdr = self.header
        interp = [s for s in self.segments if s.header.p_type == ProgramType.PT_INTERP]
        if len(interp) == 0:
            return

        # Get the interp
        interp_seg = [s for s in self.segments if s.header.p_type == ProgramType.PT_INTERP][0]
        interp_sym = [s for s in self.symbols if s.header.st_value == interp_seg.header.p_vaddr][0]

        interp_seg.header.p_offset += hdr.e_phentsize
        interp_seg.header.p_vaddr += hdr.e_phentsize
        interp_seg.header.p_paddr += hdr.e_phentsize

        interp_sec = self.get_section('.interp')
        interp_sec.header.sh_offset += hdr.e_phentsize
        interp_sec.header.sh_addr += hdr.e_phentsize

        interp_sym.header.st_value += hdr.e_phentsize

        # Move the interp data over the notes section
        start = interp_seg.header.p_offset
        end = interp_seg.header.p_offset + interp_seg.header.p_filesz
        assert (end - start == len(interp_seg.data))
        self.data[start:end] = interp_seg.data

    def shift_sections(self, size):
        hdr = self.header

        # Create space for the new segment in the program header, and find the closest gap to fill
        idx = hdr.e_phoff + hdr.e_phentsize * hdr.e_phnum
        gap_idx = self._get_gap_idx(idx+hdr.e_phentsize, hdr.e_phentsize)
        gap_idx += hdr.e_phentsize  # The gap hasn't taken into account the shift just yet
        self._full_data[idx:idx] = b'\0'*hdr.e_phentsize

        # Create the new segment
        new_segment = self._create_new_segment(size)
        self.segments.append(new_segment)
        hdr.e_phnum += 1  # TODO: This should possibly shift the PHDR size by e_phentsize (both segment and section)

        # Delete e_phentsize bytes at the first available null sequence that's large enough
        del self._full_data[gap_idx:gap_idx+hdr.e_phentsize]

        # Modify the offsets of all affected segments/sections, and the data within
        for segment in self.segments:

            # The program header's data is expected to change, hence the false verification input
            if segment.header.p_type == ProgramType.PT_PHDR:
                segment.shift(idx, gap_idx, hdr.e_phentsize, False)
                continue
            segment.shift(idx, gap_idx, hdr.e_phentsize)

        for section in self.sections:
            section.shift(idx, gap_idx, hdr.e_phentsize, self.virtual_base)

        return

    def _create_new_segment(self, size):
        """
        Creates a new Segment object at the correct alignment/offset within the binary and populates the header with
        the correct values and data. This also appends the data into the correct place after the binary's data.
        of the ELF binary.

        :param size: The length of the data to load into the Segment
        :return: A new Segment object with the data/header values populated
        """

        hdr = self.header
        last_segment = sorted(self.segments, key=lambda x: x.header.p_offset + x.header.p_filesz)[-1]
        end_addr = len(self.data)

        # Segment header values - offset at the specific alignment
        p_type = ProgramType.PT_LOAD
        p_flags = 0x5
        p_align = 0x1000
        addr_space = 0xffffffffffffffff

        # Make sure the segment is located at the correct alignment
        bitmask = addr_space ^ abs((1 - p_align))
        p_offset = (end_addr + p_align) & bitmask
        p_vaddr = (last_segment.header.p_vaddr + last_segment.header.p_memsz + p_align) & bitmask
        p_paddr = (last_segment.header.p_paddr + last_segment.header.p_memsz + p_align) & bitmask

        # Add padding to the alignment
        pad_len = p_offset - end_addr
        self.data[end_addr:p_offset] = b'\x00' * pad_len

        # Add data to elf
        self.data[p_offset:p_offset] = b'\x00' * size

        header = (
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            size,  # p_filesz
            size,  # p_memsz
            p_align
        )
        return Segment(self._full_data, hdr.e_phnum, hdr.e_phoff, hdr.e_phentsize, header)

    def _get_gap_idx(self, from_offset, size):
        """ Find the lowest offset gap of null values of a specified size between sections/segments.

        :param from_offset: Start offset to search from
        :param size: Size in bytes of the gap to find
        :return: A byte-offset of the lowest found gap between segments/sections large enough for use
        """
        # Create a dictionary of start/end offsets for all sections and segments within the binary
        start_end_offsets = set(
            [(x.header.p_offset, x.header.p_offset + x.header.p_filesz) for x in self.segments] +
            [(x.header.sh_offset, x.header.sh_offset + x.header.sh_size) for x in self.sections]
        )

        not_within = []
        for start, end in start_end_offsets:

            # Ignore entities prior to where we're looking
            if end < from_offset:
                continue

            # Remove those entries that are contained within other entries
            if not self._are_values_within(start, end, start_end_offsets):
                not_within.append((start, end))

        # Extend elements that are overlapping
        non_overlapping = self._extend_overlapping(not_within)

        # Find the gaps
        non_overlapping.sort(key=lambda x: x[0])
        for start, end in non_overlapping:
            index = non_overlapping.index((start, end))
            closest = next(iter(sorted(
                [(x, y) for x, y in non_overlapping[index:]
                 if x >= end],
                key=lambda x: x[0])), None)

            # Ensure the gap is big enough, and the data contains null values
            if closest is not None and closest[0] - end >= size \
                    and self._full_data[end:end+size] == b"\0"*size:
                return end

        raise ValueError("No gap found")

    @staticmethod
    def _are_values_within(start, end, offsets):
        """ Given a list of tuples containing start/end values, check whether the start and end parameter are contained
        within any of those tuples, ie. the start->end range is contained within any other start->end range in the list.

        Start and end values that are equivalent are ignored, due to the assumption that they are the same values.

        :param start: Start of the range to check
        :param end: End of the range to check
        :param offsets: List of (start, end) tuples to check against
        :return: True if start, end is contained within another tuple, otherwise false
        """
        for start_comp, end_comp in offsets:
            if start == start_comp and end == end_comp:
                continue
            if start >= start_comp and end <= end_comp:
                return False
        return True

    @staticmethod
    def _extend_overlapping(offsets):
        """ Given a set of start->end offset tuples, merge the set so that any overlapping or contiguous arrays are
        merged into a single start->end value.

        :param offsets: List of (start,end) tuple values
        :return: List of (start,end) tuple values with no overlaps
        """
        offsets.sort(key=lambda x: x[0])
        result = []
        i = 0
        while i < len(offsets) - 1:

            # Get the initial start/end values
            start, end = offsets[i]

            # If the next start value falls on or before the current end value, extend the current end value
            # and continue on to the next tuple
            while i < len(offsets)-1 and end >= offsets[i+1][0]:
                end = offsets[i+1][1]
                i += 1

            # Once they're not contiguous we can add the result to the list and keep going
            result.append((start, end))
            i += 1

        return result

    @staticmethod
    def _extract_header_names(data):
        return [x for x in data.decode("utf-8").split('\0')]


class Function:
    """ A helper class for returning details of specific functions within the binary """

    def __init__(self, name, offset, size):
        """
        Initialises a new Function given it's name, offset and size.
        :param name: The name of the function (from a symbol if available, otherwise randomly generated)
        :param offset: The address of the function in bytes within the binary
        :param size: The lenght of the function in bytes
        """
        self.name = name
        self.start_addr = offset
        self.size = size
        self.end_addr = offset + size

    def __str__(self):
        return f"{self.name} @ 0x{self.start_addr:x}"

# TODO: Consider turning these into tests
def hash_table():
    filename = '/home/james/dev/offside-trap/test/bin/strings'
    elf = ELF(filename)
    ht = elf.get_section('.hash')
    sym = elf.sections[ht.header.sh_link].symbol_table
    for st in sym:
        found = ht.find(st.symbol_name)
        print(f"{st.symbol_name}: {found}")
    x = ht.find('asdfasdf')
    print(x)

def gnu_hash_table():
    filename = '/home/james/dev/offside-trap/test/bin/strings'
    elf = ELF(filename)
    ht = elf.get_section('.gnu.hash')
    elf.shift_sections(400)
    sym = elf.sections[ht.header.sh_link].symbol_table
    for st in sym[ht.hash_table.symoffset:]:
        found = ht.find(st.symbol_name)
        print(f"{st.symbol_name}: {found}")
    x = ht.find('asdfasdf')
    print(x)

def pack_file():
    filename = '/home/james/dev/offside-trap/test/source/test'
    packed_filename = f"{filename}.packed"
    elf = ELF(filename)
    elf.header.e_phnum = 9
    elf.header.e_ident.el_osabi = ELFOSABI.ELFOSABI_OPENVMS

    # Regular segment
    elf.segments[1].header.p_offset = 0x3a8
    elf.segments[1].header.p_type = ProgramType.PT_HIPROC

    # Dynamic segment
    elf.segments[6].dynamic_table[0].d_tag = DynamicTag.DT_CHECKSUM

    # Regular section
    elf.sections[13].header.sh_offset = 0x8000
    elf.sections[13].header.sh_type = SectionType.SHT_GNU_INCREMENTAL_INPUTS

    # Dynamic section
    elf.sections[20].dynamic_table[3].d_un = 10000

    # Symbol table section
    elf.sections[5].symbol_table[2].header.st_name = 4
    elf.sections[5].symbol_table[2].header.st_info.st_bind = SymbolBinding.STB_LOPROC

    # Hash section

    # Gnu hash section
    elf.sections[4].hash_table.bucket[0] = 10

    # Relocation section
    elf.sections[9].relocation_table[0].r_offset = 0x1000
    elf.sections[9].relocation_table[0].r_addend = 0x1000
    elf.sections[9].relocation_table[3].r_info.r_type = RelocationType.R_X86_64_GOTPLT64

    # String table section

    elf.append_loadable_segment_3(400)
    #elf.segments[6].dynamic_table[7].d_un = 1024
    with open(packed_filename, 'wb') as f:
        f.write(elf.data)

def pack_file_2():
    filename = '/home/james/dev/offside-trap/test/source/test'
    packed_filename = f"{filename}.packed"
    elf = ELF(filename)
    elf.shift_sections(400)

    with open(packed_filename, 'wb') as f:
        f.write(elf.data)

if __name__ == '__main__':
    pack_file_2()
