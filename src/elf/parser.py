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
        self._set_headers()

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
        new_segment = self._create_new_segment(size + self.phdr.header.p_filesz)
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

        # Get the segment loading the program header
        phdr_segment = [s for s in self.segments
                        if s.header.p_type == ProgramType.PT_LOAD
                        and s.header.p_offset <= self.phdr.header.p_offset
                        and s.header.p_offset + s.header.p_filesz >= self.phdr.header.p_offset + self.phdr.header.p_filesz][0]
        phdr_start = phdr_segment.header.p_offset
        phdr_end = phdr_start + phdr_segment.header.p_filesz
        next_segment_start = sorted([s for s in self.segments if s.header.p_offset >= phdr_end], key=lambda x: x.header.p_offset)[0].header.p_offset

        # Create space for the new segment in the program header
        idx = hdr.e_phoff + hdr.e_phentsize * hdr.e_phnum
        self._full_data[idx:idx] = b'\0'*hdr.e_phentsize

        # Create the new segment
        new_segment = self._create_new_segment(size)
        self.segments.append(new_segment)
        hdr.e_phnum += 1  # TODO: This should possibly shift the PHDR size by e_phentsize (both segment and section)

        # Delete e_phentsize bytes at the first available null sequence that's large enough
        # Only search between the range within the phdr load segment, after the new phdr index data
        try:
            null_start = self._full_data.index(b'\0'*hdr.e_phentsize, idx+hdr.e_phentsize, next_segment_start+hdr.e_phentsize)
        except ValueError as ex:
            print(f"Cannot find a sequence of null bytes large enough to move into")
            raise

        del self._full_data[null_start:null_start+hdr.e_phentsize]

        affected = [s for s in self.segments
                    if s.header.p_offset + s.header.p_filesz >= idx
                    and s.header.p_offset <= null_start]

        for segment in self.segments:
            if segment.header.p_type == ProgramType.PT_PHDR:
                segment.shift(idx, null_start, hdr.e_phentsize, False)
                continue
            segment.shift(idx, null_start, hdr.e_phentsize)

        affected = [s for s in self.sections
                    if s.header.sh_offset + s.header.sh_size >= idx
                    and s.header.sh_offset <= null_start]

        for section in self.sections:
            section.shift(idx, null_start, hdr.e_phentsize)

        return

        # Shift the offsets of affected segments
        affected = [s for s in self.segments
                    if s.header.p_offset + s.header.p_filesz >= idx
                    and s.header.p_offset <= null_start]

        for segment in affected:
            # Move the start only if it's after the index
            if segment.header.p_offset >= idx:
                segment.header.p_offset += hdr.e_phentsize
                segment.header.p_paddr += hdr.e_phentsize
                segment.header.p_vaddr += hdr.e_phentsize
            # Otherwise increase the size
            else:
                segment.header.p_filesz += hdr.e_phentsize
                segment.header.p_memsz += hdr.e_phentsize

            if segment.header.p_type != ProgramType.PT_PHDR:
                assert(segment.data[:self.header.e_phentsize] == segment.live_data[:self.header.e_phentsize])
                assert(segment.data[-self.header.e_phentsize:] == segment.live_data[-self.header.e_phentsize:])

        # Shift the offsets of affected sections
        affected = [s for s in self.sections
                    if s.header.sh_offset + s.header.sh_size >= idx
                    and s.header.sh_offset <= null_start]

        for section in affected:
            # Move the start only if it's after the index
            if section.header.sh_offset >= idx:
                section.header.sh_offset += hdr.e_phentsize
                section.header.sh_addr += hdr.e_phentsize
            # Otherwise increase the size
            else:
                section.header.sh_size += hdr.e_phentsize

            assert(section.data == section.live_data)

    def append_loadable_segment_2(self, size):

        hdr = self.header

        # Get the segment loading the program header
        phdr_segment = [s for s in self.segments
                        if s.header.p_type == ProgramType.PT_LOAD
                        and s.header.p_offset <= self.phdr.header.p_offset
                        and s.header.p_offset + s.header.p_filesz >= self.phdr.header.p_offset + self.phdr.header.p_filesz][0]

        # Increase the size of the segment to account for the new segment being added
        phdr_segment.header.p_filesz += hdr.e_phentsize
        phdr_segment.header.p_memsz += hdr.e_phentsize

        # Shift any segments after the program header over by the size of an entry
        marker = self.phdr.header.p_offset + self.phdr.header.p_filesz
        self._shift_data(marker)
        self._shift_segments(marker)
        self._shift_sections(marker)

        # Create new segment
        new_segment = self._create_new_segment(size)
        packed = pack(new_segment.hdr_struct, *new_segment.header)
        self.segments.append(new_segment)

        # Add header to end of header section
        offset = hdr.e_phoff + (hdr.e_phentsize * hdr.e_phnum)
        self._full_data[offset:offset + hdr.e_phentsize] = packed
        hdr.e_phnum += 1

        return new_segment

    def _shift_data(self, marker):
        hdr = self.header
        init_marker = marker
        next_segment = [s for s in self.segments if init_marker <= s.header.p_offset <= init_marker + hdr.e_phentsize][0]
        moved_segments = []
        p_offset = next_segment.header.p_offset
        while next_segment is not None:
            moved_segments.append(next_segment)
            marker = next_segment.header.p_offset + next_segment.header.p_filesz
            p_offset += hdr.e_phentsize
            try:
                next_segment = [s for s in self.segments
                                if marker <= s.header.p_offset <= marker + hdr.e_phentsize
                                and s not in moved_segments][0]
            except IndexError:
                next_segment = None

        moved_sections = []
        next_section = [s for s in self.sections if init_marker <= s.header.sh_offset <= init_marker + hdr.e_phentsize][0]
        sh_offset = next_section.header.sh_offset
        while next_section is not None:
            moved_sections.append(next_section)
            marker = next_section.header.sh_offset + next_section.header.sh_size
            sh_offset += hdr.e_phentsize
            try:
                next_section = [s for s in self.sections
                                if marker <= s.header.sh_offset <= marker + hdr.e_phentsize
                                and s not in moved_sections][0]
            except IndexError:
                next_section = None

        max_end = init_marker
        for segment in moved_segments:
            seg_end = segment.header.p_offset + segment.header.p_filesz
            max_end = seg_end if max_end < seg_end else max_end

        for section in moved_sections:
            sec_end = section.header.sh_offset + section.header.sh_size
            max_end = sec_end if max_end < sec_end else max_end

        self.data[init_marker + hdr.e_phentsize:max_end + hdr.e_phentsize] = self.data[init_marker:max_end]

    def _shift_segments(self, marker):
        hdr = self.header
        next_segment = [s for s in self.segments if marker <= s.header.p_offset <= marker + hdr.e_phentsize][0]
        moved_segments = []
        while next_segment is not None:
            moved_segments.append(next_segment)
            marker = next_segment.header.p_offset + next_segment.header.p_filesz
            next_segment.header.p_offset += hdr.e_phentsize
            next_segment.header.p_vaddr += hdr.e_phentsize
            try:
                next_segment = [s for s in self.segments
                                if marker <= s.header.p_offset <= marker + hdr.e_phentsize
                                and s not in moved_segments][0]
            except IndexError:
                next_segment = None

        # for segment in (sorted(moved_segments, key=lambda s: s.header.p_offset, reverse=True)):
        #     self.data[segment.header.p_offset:segment.header.p_offset + segment.header.p_filesz] = segment.data

    def _shift_sections(self, marker):
        hdr = self.header
        next_section = [s for s in self.sections if marker <= s.header.sh_offset <= marker + hdr.e_phentsize][0]
        moved_sections = []
        while next_section is not None:
            moved_sections.append(next_section)
            marker = next_section.header.sh_offset + next_section.header.sh_size
            next_section.header.sh_offset += hdr.e_phentsize
            next_section.header.sh_addr += hdr.e_phentsize
            try:
                next_section = [s for s in self.sections
                                if marker <= s.header.sh_offset <= marker + hdr.e_phentsize
                                and s not in moved_sections][0]
            except IndexError:
                next_section = None

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

    @staticmethod
    def _extract_header_names(data):
        return [x for x in data.decode("utf-8").split('\0')]

    def _set_headers(self):
        """
        Sets the program header and section header as properties within the ELF object.
        """

        # Program Header
        if self.linking_method == ELFLinkingMethod.DYNAMIC:
            self.phdr = [x for x in self.segments if x.header.p_type == ProgramType.PT_PHDR][0]
        else:
            # Create a new "ghost" segment containing the correct data, without adding it to the segment list
            hdr = self.header
            header = (
                ProgramType.PT_PHDR,  # p_type
                4,  # p_flags
                hdr.e_phoff,  # p_offset
                hdr.e_phoff,  # p_vaddr
                hdr.e_phoff,  # p_paddr
                hdr.e_phentsize * hdr.e_phnum,  # p_filesz
                hdr.e_phentsize * hdr.e_phnum,  # p_memsz
                8  # p_align
            )
            self.phdr = Segment(self._full_data, 0, hdr.e_phoff, hdr.e_phentsize, header)

        # TODO: Section Header


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
