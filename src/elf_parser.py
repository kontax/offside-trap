from struct import unpack, pack

import r2pipe

from elf_enums import *
from elf_section import Section
from elf_segment import Segment, SegmentFactory
from elf_symbol import Symbol

"""
ELF Specification: http://ftp.openwatcom.org/devel/docs/elf-64-gen.pdf
"""


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


def repack_header(data, hdr_offset, hdr_size, hdr, hdr_struct):
    end_offset = hdr_offset + hdr_size
    data[hdr_offset:end_offset] = pack(hdr_struct, *hdr)


class ELFIdent:
    """ e_ident containing identification details of the ELF file """

    def __init__(self, header):
        self.data = header
        self.el_mag = header[0:4]
        assert (self.el_mag == b"\x7fELF")
        self.el_class = ELFClass(header[4])
        self.el_data = ELFData(header[5])
        self.el_version = header[6]
        self.el_osabi = ELFOSABI(header[7])
        self.el_abiversion = header[8]
        self.el_pad = header[9:15]
        self.el_nident = header[15]


class ELF:
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
    def header(self):
        """ Gets the tuple containing the values within the header of the entity """
        return (
            self.e_ident.data,
            self.e_type.value,
            self.e_machine.value,
            self.e_version,
            self._e_entry,
            self._e_phoff,
            self._e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self._e_phnum,
            self.e_shentsize,
            self._e_shnum,
            self.e_shstrndx
        )

    @property
    def e_entry(self):
        """ Gets or sets the entry point of the program """
        return self._e_entry

    @e_entry.setter
    def e_entry(self, value):
        self._e_entry = value
        self._repack_header()

    @property
    def e_phoff(self):
        """ Gets or sets the program header offset """
        return self._e_phoff

    @e_phoff.setter
    def e_phoff(self, value):
        self._e_phoff = value
        for seg in self.segments:
            seg.e_phoff = value
        self._repack_header()

    @property
    def e_shoff(self):
        """ Gets or sets the section header offset """
        return self._e_shoff

    @e_shoff.setter
    def e_shoff(self, value):
        self._e_shoff = value
        self._repack_header()

    @property
    def e_phnum(self):
        """ Gets or sets the number of program headers """
        return self._e_phnum

    @e_phnum.setter
    def e_phnum(self, value):
        self._e_phnum = value
        self._repack_header()

    @property
    def e_shnum(self):
        """ Gets or sets the number of section headers """
        return self._e_shnum

    @e_shnum.setter
    def e_shnum(self, value):
        self._e_shnum = value
        self._repack_header()

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
        self.hdr_struct = "16sHHIQQQIHHHHHH"
        self.hdr_size = 64  # TODO: This is contained in the header as e_ehsize
        self.segments = []
        self.sections = []
        self.symbols = []
        (
            self.e_ident,
            self.e_type,
            self.e_machine,
            self.e_version,
            self._e_entry,
            self._e_phoff,
            self._e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self._e_phnum,
            self.e_shentsize,
            self._e_shnum,
            self.e_shstrndx
        ) = self._parse_header(self.data, self.hdr_size, self.hdr_struct)

        # Pull the data containing the segment names initially
        shstrtab_data = Section(self.data, self.e_shstrndx, self.e_shoff, self.e_shentsize).data

        # Extract the Segments
        for i in range(self.e_phnum):
            self.segments.append(SegmentFactory.create_segment(self.data, i, self.e_phoff, self.e_phentsize))

        # Extract the Sections
        for i in range(self.e_shnum):
            self.sections.append(Section(self.data, i, self.e_shoff, self.e_shentsize, shstrtab_data))

        # Associate each section with the segment it's contained within
        for s in self.segments:
            s.load_sections(self.sections)

        # Whether the ELF is statically or dynamically linked
        self._linking_method = ELFLinkingMethod(len([x for x in self.sections if x.section_name == '.interp']))

        # Extract the Symbols
        symtab = next(iter([x for x in self.sections if x.section_name == '.symtab']), None)
        strtab = next(iter([x for x in self.sections if x.section_name == '.strtab']), None)

        # Take stripped binaries into account
        if symtab is not None:
            for i in range(int(symtab.sh_size / symtab.sh_entsize)):
                self.symbols.append(Symbol(self.data, i, symtab.sh_offset, symtab.sh_entsize, strtab.data))

        # Associate each symbol with the section it's contained within
        for s in self.sections:
            s.load_symbols(self.symbols)

        self._virtual_base = min(x.p_vaddr for x in self.segments if x.p_type == ProgramType.PT_LOAD)
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
            func_symbols = [Function(fn.symbol_name, fn.st_value, fn.st_size)
                            for fn in text.symbols
                            if fn.st_info.st_type == SymbolType.STT_FUNC]  # All functions
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
        assert (len(sections) == 1)
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

        # Create a new segment
        new_segment = self._create_new_segment(size + self.phdr.p_filesz)
        packed = pack(new_segment.hdr_struct, *new_segment.header)
        self.segments.append(new_segment)

        # Add header entry to end of header section
        offset = self.e_phoff + (self.e_phentsize * self.e_phnum)
        self._full_data[offset:offset + self.e_phentsize] = packed
        self.e_phnum += 1

        return new_segment

    def _shift_interp(self):
        """
        Shifts the INTERP section/segment/symbol in order to make room for a new header section. This overwrites
        any data after this section, which is hopefully unused.
        """
        interp = [s for s in self.segments if s.p_type == ProgramType.PT_INTERP]
        if len(interp) == 0:
            return

        # Get the interp
        interp_seg = [s for s in self.segments if s.p_type == ProgramType.PT_INTERP][0]
        interp_sym = [s for s in self.symbols if s.st_value == interp_seg.p_vaddr][0]

        interp_seg.p_offset += self.e_phentsize
        interp_seg.p_vaddr += self.e_phentsize
        interp_seg.p_paddr += self.e_phentsize

        interp_sec = self.get_section('.interp')
        interp_sec.sh_offset += self.e_phentsize
        interp_sec.sh_addr += self.e_phentsize

        interp_sym.st_value += self.e_phentsize

        # Move the interp data over the notes section
        start = interp_seg.p_offset
        end = interp_seg.p_offset + interp_seg.p_filesz
        assert (end - start == len(interp_seg.data))
        self.data[start:end] = interp_seg.data

    def append_loadable_segment_2(self, size):

        # Get the segment loading the program header
        phdr_segment = [s for s in self.segments
                        if s.p_type == ProgramType.PT_LOAD
                        and s.p_offset <= self.phdr.p_offset
                        and s.p_offset + s.p_filesz >= self.phdr.p_offset + self.phdr.p_filesz][0]

        # Increase the size of the segment to account for the new segment being added
        phdr_segment.p_filesz += self.e_phentsize
        phdr_segment.p_memsz += self.e_phentsize

        # Shift any segments after the program header over by the size of an entry
        marker = self.phdr.p_offset + self.phdr.p_filesz
        self._shift_data(marker)
        self._shift_segments(marker)
        self._shift_sections(marker)

        # Create new segment
        new_segment = self._create_new_segment(size)
        packed = pack(new_segment.hdr_struct, *new_segment.header)
        self.segments.append(new_segment)

        # Add header to end of header section
        offset = self.e_phoff + (self.e_phentsize * self.e_phnum)
        self._full_data[offset:offset + self.e_phentsize] = packed
        self.e_phnum += 1

        return new_segment

    def _shift_data(self, marker):
        init_marker = marker
        next_segment = [s for s in self.segments if init_marker <= s.p_offset <= init_marker + self.e_phentsize][0]
        moved_segments = []
        p_offset = next_segment.p_offset
        while next_segment is not None:
            moved_segments.append(next_segment)
            marker = next_segment.p_offset + next_segment.p_filesz
            p_offset += self.e_phentsize
            try:
                next_segment = [s for s in self.segments
                                if marker <= s.p_offset <= marker + self.e_phentsize
                                and s not in moved_segments][0]
            except IndexError:
                next_segment = None

        moved_sections = []
        next_section = [s for s in self.sections if init_marker <= s.sh_offset <= init_marker + self.e_phentsize][0]
        sh_offset = next_section.sh_offset
        while next_section is not None:
            moved_sections.append(next_section)
            marker = next_section.sh_offset + next_section.sh_size
            sh_offset += self.e_phentsize
            try:
                next_section = [s for s in self.sections
                                if marker <= s.sh_offset <= marker + self.e_phentsize
                                and s not in moved_sections][0]
            except IndexError:
                next_section = None

        max_end = init_marker
        for segment in moved_segments:
            seg_end = segment.p_offset + segment.p_filesz
            max_end = seg_end if max_end < seg_end else max_end

        for section in moved_sections:
            sec_end = section.sh_offset + section.sh_size
            max_end = sec_end if max_end < sec_end else max_end

        self.data[init_marker + self.e_phentsize:max_end + self.e_phentsize] = self.data[init_marker:max_end]

    def _shift_segments(self, marker):
        next_segment = [s for s in self.segments if marker <= s.p_offset <= marker + self.e_phentsize][0]
        moved_segments = []
        while next_segment is not None:
            moved_segments.append(next_segment)
            marker = next_segment.p_offset + next_segment.p_filesz
            next_segment.p_offset += self.e_phentsize
            next_segment.p_vaddr += self.e_phentsize
            try:
                next_segment = [s for s in self.segments
                                if marker <= s.p_offset <= marker + self.e_phentsize
                                and s not in moved_segments][0]
            except IndexError:
                next_segment = None

        # for segment in (sorted(moved_segments, key=lambda s: s.p_offset, reverse=True)):
        #     self.data[segment.p_offset:segment.p_offset + segment.p_filesz] = segment.data

    def _shift_sections(self, marker):
        next_section = [s for s in self.sections if marker <= s.sh_offset <= marker + self.e_phentsize][0]
        moved_sections = []
        while next_section is not None:
            moved_sections.append(next_section)
            marker = next_section.sh_offset + next_section.sh_size
            next_section.sh_offset += self.e_phentsize
            next_section.sh_addr += self.e_phentsize
            try:
                next_section = [s for s in self.sections
                                if marker <= s.sh_offset <= marker + self.e_phentsize
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

        last_segment = sorted(self.segments, key=lambda x: x.p_offset + x.p_filesz)[-1]
        end_addr = len(self.data)

        # Segment header values - offset at the specific alignment
        p_type = ProgramType.PT_LOAD
        p_flags = 0x5
        p_align = 0x1000
        addr_space = 0xffffffffffffffff

        # Make sure the segment is located at the correct alignment
        bitmask = addr_space ^ abs((1 - p_align))
        p_offset = (end_addr + p_align) & bitmask
        p_vaddr = (last_segment.p_vaddr + last_segment.p_memsz + p_align) & bitmask
        p_paddr = (last_segment.p_paddr + last_segment.p_memsz + p_align) & bitmask

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
        return Segment(self._full_data, self.e_phnum, self.e_phoff, self.e_phentsize, header)

    @staticmethod
    def _parse_header(data, header_size, hdr_struct):
        """
        Parses the bytearray data to extract the header values.

        :param data: The bytearray containing the data of the binary.
        :param header_size: The size of the ELF header in bytes.
        :param hdr_struct: The code used to parse the header within struct.pack()
        :return: A set of ELF header values for the current binary.
        """
        header = unpack(hdr_struct, data[:header_size])
        return (
            ELFIdent(header[0]),  # e_ident
            ELFFileType(header[1]),  # e_type
            ELFMachine(header[2]),  # e_machine
            header[3],  # e_version
            header[4],  # e_entry
            header[5],  # e_phoff
            header[6],  # e_shoff
            header[7],  # e_flags
            header[8],  # e_ehsize
            header[9],  # e_phentsize
            header[10],  # e_phnum
            header[11],  # e_shentsize
            header[12],  # e_shnum
            header[13],  # e_shstrndx
        )

    @staticmethod
    def _extract_header_names(data):
        return [x for x in data.decode("utf-8").split('\0')]

    def _set_headers(self):
        """
        Sets the program header and section header as properties within the ELF object.
        """

        # Program Header
        if self.linking_method == ELFLinkingMethod.DYNAMIC:
            self.phdr = [x for x in self.segments if x.p_type == ProgramType.PT_PHDR][0]
        else:
            # Create a new "ghost" segment containing the correct data, without adding it to the segment list
            header = (
                ProgramType.PT_PHDR,  # p_type
                4,  # p_flags
                self.e_phoff,  # p_offset
                self.e_phoff,  # p_vaddr
                self.e_phoff,  # p_paddr
                self.e_phentsize * self.e_phnum,  # p_filesz
                self.e_phentsize * self.e_phnum,  # p_memsz
                8  # p_align
            )
            self.phdr = Segment(self._full_data, 0, self.e_phoff, self.e_phentsize, header)

        # TODO: Section Header

    def _repack_header(self):
        """ Re-packs the header once edits have been made, so as to propogate any changes within the binary data """
        repack_header(self._full_data, 0, self.e_ehsize, self.header, self.hdr_struct)


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


if __name__ == '__main__':
    filename = '/home/james/dev/offside-trap/test/source/test'
    packed_filename = f"{filename}.packed"
    elf = ELF(filename)
    #elf.append_loadable_segment_2(400)
    elf.segments[6].dynamic_table[7].d_un = 1024
    with open(packed_filename, 'wb') as f:
        f.write(elf.data)
