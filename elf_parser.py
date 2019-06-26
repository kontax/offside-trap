from elf_enums import *
from struct import unpack, pack

"""
ELF Specification: http://ftp.openwatcom.org/devel/docs/elf-64-gen.pdf
"""


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

    def __init__(self, data):
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
            self.segments.append(Segment(self.data, i, self.e_phoff, self.e_phentsize))

        # Extract the Sections
        for i in range(self.e_shnum):
            self.sections.append(Section(self.data, i, self.e_shoff, self.e_shentsize, shstrtab_data))

        # Extract the Symbols
        symtab = [x for x in self.sections if x.section_name == '.symtab'][0]
        strtab = [x for x in self.sections if x.section_name == '.strtab'][0]
        for i in range(int(symtab.sh_size / symtab.sh_entsize)):
            self.symbols.append(Symbol(self.data, i, symtab.sh_offset, symtab.sh_entsize, strtab.data))

        self._virtual_base = min(x.p_vaddr for x in self.segments if x.p_type == ProgramType.PT_LOAD)

    def append_data_segment(self, data):
        """
        1. Find the first empty space within the file
            a. Gap with enough space
            b. Lowest possible address
            c. Is not contained within any other segments
        2. Copy the program header to that space
        3. Add the additional entry
        4. Modify the elf headers
        :return:
        """

        # Statically linked files don't have a PT_PHDR segment - the program header is in the first PT_LOAD segment
        program_headers = [x for x in self.segments if x.p_type == ProgramType.PT_PHDR]
        if len(program_headers) > 0:
            p_header = program_headers[0]
        else:
            p_header = [x for x in self.segments if x.p_offset <= self.e_phoff <= x.p_offset + x.p_filesz][0]
        size_needed = p_header.p_filesz + self.e_phentsize
        gap_segments = self._get_gap_segments(size_needed)

        old_start = p_header.p_offset
        old_end = p_header.p_offset + p_header.p_filesz
        old_size = old_end - old_start

        # Copy existing header and data
        start = gap_segments[0].p_offset + gap_segments[0].p_filesz
        self.data[start:start + old_size] = p_header.data

        # Modify the header values
        self.e_phoff = start
        p_header.p_offset = start
        p_header.p_vaddr = self.virtual_base + start
        self.data[old_start:old_end] = b'\x00' * (old_end - old_start)

        # Remap LOAD segment
        # See above about statically linked files
        if p_header.p_type == ProgramType.PT_PHDR:
            load_segment = [x for x in self.segments
                            if x.p_offset <= old_start <= x.p_offset + x.p_filesz
                            and x.p_type == ProgramType.PT_LOAD][0]
            load_segment.p_filesz += p_header.p_filesz
            load_segment.p_memsz += p_header.p_memsz
        else:
            load_segment = p_header

        # Create new segment
        new_segment = self._create_segment(data)
        packed = pack(new_segment.hdr_struct, *new_segment.header)
        self.segments.append(new_segment)

        # Add header to end of header section
        offset = self.e_phoff + (self.e_phentsize * self.e_phnum)
        self._full_data[offset:offset + self.e_phentsize] = packed
        self.e_phnum += 1
        p_header.p_filesz += self.e_phentsize
        p_header.p_memsz += self.e_phentsize

        load_segment.p_filesz += p_header.p_filesz
        load_segment.p_memsz += p_header.p_memsz

    def _create_segment(self, data):

        last_segment = sorted(self.segments, key=lambda x: x.p_offset+x.p_filesz)[-1]
        #end_addr = last_segment.p_offset + last_segment.p_filesz
        end_addr = len(self.data)
        addr_space = 0xffffffffffffffff

        # Segment header values - offset at the specific alignment
        p_type = ProgramType.PT_LOAD
        p_flags = 0x5
        p_align = 0x1000

        # Make sure the segment is located at the correct alignment
        bitmask = addr_space ^ abs((1 - p_align))
        p_offset = (end_addr + p_align) & bitmask
        p_vaddr = (last_segment.p_vaddr + last_segment.p_memsz + p_align) & bitmask
        p_paddr = (last_segment.p_paddr + last_segment.p_memsz + p_align) & bitmask

        # Add padding to the alignment
        pad_len = p_offset - end_addr
        self.data[end_addr:p_offset] = b'\x00' * pad_len

        # Add data to elf
        self.data[p_offset:p_offset] = data

        header = (
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            len(data),  # p_filesz
            len(data),  # p_memsz
            p_align
        )
        return Segment(self._full_data, self.e_phnum, self.e_phoff, self.e_phentsize, header)

    def _get_gap_segments(self, size_needed):

        # If there is a gap after the program header large enough, then that is fine

        sorted_segments = [x for x in self.segments if x.p_filesz > 0]
        sorted_segments.sort(key=lambda x: x.p_offset)
        gap_segments = None
        for segment in sorted_segments:
            segment_end_addr = segment.p_offset + segment.p_filesz
            # Find the closest segment
            index = sorted_segments.index(segment)
            closest_segment = next(iter(sorted(
                [x for x in sorted_segments[index:]
                 if x.p_offset >= segment.p_offset + segment.p_filesz],
                key=lambda x: x.p_offset)), None)

            if closest_segment is None:
                continue

            # Check if the gap between is big enough
            if closest_segment.p_offset - segment_end_addr < size_needed:
                continue

            # Make sure no other segments are in the way
            if self.is_segment_overlapped(segment, closest_segment):
                continue

            # First time then save
            if gap_segments is None:
                gap_segments = (segment, closest_segment)
                continue

            # Get the one with the lowest address
            if closest_segment.p_offset < gap_segments[1].p_offset:
                gap_segments = (segment, closest_segment)

        # Ensure we've found a large enough gap
        assert (gap_segments is not None)

        return gap_segments

    def is_segment_overlapped(self, first_segment, next_segment):
        start = first_segment.p_offset + first_segment.p_filesz
        end = next_segment.p_offset
        for segment in self.segments:

            # Don't need to check the current segments
            if segment is first_segment or segment is next_segment:
                continue

            segment_end = segment.p_offset + segment.p_filesz

            # Check segments within the gap
            if start <= segment.p_offset <= end \
                    or start <= segment_end <= end:
                return True

            # Check segments overlapping the gap entirely
            if segment.p_offset <= start and segment_end >= end:
                return True

        return False

    def append_segment(self, p_type: ProgramType, p_flags: int, data: bytearray):

        # Get last segment address and size
        last_segment = sorted(self.segments, key=lambda x: x.p_offset)[-1]
        loc_in_file = last_segment.p_offset + last_segment.p_filesz

        # Check out alignment stuff
        p_align = 0x1000
        padding_len = p_align - ((len(data) + self.e_phentsize) & 0xfff)
        padding_data = bytearray(b'\0' * padding_len)
        data[len(data):] = padding_data

        # Add data to end of file
        self._full_data[loc_in_file:loc_in_file] = data

        # Increase segment count in main header
        self.e_phnum += 1

        # Create new segment
        header = (
            p_type,
            p_flags,
            last_segment.p_offset + last_segment.p_filesz,  # p_offset
            last_segment.p_vaddr + last_segment.p_memsz,  # p_vaddr
            last_segment.p_paddr + last_segment.p_memsz,  # p_paddr
            len(data),  # p_filesz
            len(data),  # p_memsz
            p_align
        )
        new_segment = Segment(self._full_data, self.e_phnum, self.e_phoff, self.e_phentsize, header)
        packed = pack(new_segment.hdr_struct, *new_segment.header)

        # Add header to end of header section
        offset = self.e_phoff + (self.e_phentsize * self.e_phnum)
        self._full_data[offset:offset] = packed

        # Update the location of the section headers
        self.e_shoff += self.e_phentsize + len(data)

        # Move everything over - including all references to addresses - by offset of header
        for s in self.sections:
            s.e_shoff = self.e_shoff
            if s.sh_addr > 0:
                s.sh_addr += self.e_phentsize
            if s.sh_offset > 0:
                if s.sh_offset > offset:
                    s.sh_offset += self.e_phentsize + len(data)
                else:
                    s.sh_offset += self.e_phentsize

        for s in self.segments:
            if s.p_offset > 0:
                s.p_offset += self.e_phentsize
            if s.p_vaddr > 0:
                s.p_vaddr += self.e_phentsize
            if s.p_paddr > 0:
                s.p_paddr += self.e_phentsize

        for s in self.symbols:
            s.sh_offset += self.e_phentsize + len(data)
            if s.st_value > 0:
                s.st_value += self.e_phentsize + len(data)
            # Get everything after offset
            # Add self.e_phentsize to each address

    @staticmethod
    def _parse_header(data, header_size, hdr_struct):
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

    def _repack_header(self):
        repack_header(self._full_data, 0, self.e_ehsize, self.header, self.hdr_struct)


class Segment:
    """ Program Header
    Elf64_Word      p_type;         /* Type of segment */
    Elf64_Word      p_flags;        /* Segment attributes */
    Elf64_Off       p_offset;       /* Offset in file */
    Elf64_Addr      p_vaddr;        /* Virtual address in memory */
    Elf64_Addr      p_paddr;        /* Reserved */
    Elf64_Xword     p_filesz;       /* Size of segment in file */
    Elf64_Xword     p_memsz;        /* Size of segment in memory */
    Elf64_Xword     p_align;        /* Alignment of segment */
    """

    @property
    def header(self):
        """ Gets the tuple containing the values within the header of the entity """
        return (
            self._p_type.value,
            self._p_flags,
            self._p_offset,
            self._p_vaddr,
            self._p_paddr,
            self._p_filesz,
            self._p_memsz,
            self._p_align
        )

    @property
    def p_type(self):
        """ Gets or sets the type of segment """
        return self._p_type

    @p_type.setter
    def p_type(self, value):
        self._p_type = value
        self._repack_header()

    @property
    def p_flags(self):
        """ Gets or sets the flags of the segment """
        return self._p_flags

    @p_flags.setter
    def p_flags(self, value):
        self._p_flags = value
        self._repack_header()

    @property
    def p_offset(self):
        """ Gets or sets the offset of the program header within the file """
        return self._p_offset

    @p_offset.setter
    def p_offset(self, value):
        self._p_offset = value
        self._repack_header()

    @property
    def p_vaddr(self):
        """ Gets or sets the virtual address of the segment within memory """
        return self._p_vaddr

    @p_vaddr.setter
    def p_vaddr(self, value):
        self._p_vaddr = value
        self._repack_header()

    @property
    def p_paddr(self):
        """ Gets or sets some reserved bytes in memory """
        return self._p_paddr

    @p_paddr.setter
    def p_paddr(self, value):
        self._p_paddr = value
        self._repack_header()

    @property
    def p_filesz(self):
        """ Gets or sets the size of the segment within the file """
        return self._p_filesz

    @p_filesz.setter
    def p_filesz(self, value):
        self._p_filesz = value
        self._repack_header()

    @property
    def p_memsz(self):
        """ Gets or sets the size of the segment within the memory """
        return self._p_memsz

    @p_memsz.setter
    def p_memsz(self, value):
        self._p_memsz = value
        self._repack_header()

    @property
    def p_align(self):
        """ Gets or sets the alignment of the segment - must be a power of 2, with p_offset and p_vaddr
        congruent modulo the alignment """
        return self._p_align

    @p_align.setter
    def p_align(self, value):
        self._p_align = value
        self._repack_header()

    def __init__(self, data, segment_number, e_phoff, e_phentsize, header=None):
        self._full_data = data
        self.hdr_struct = "IIQQQQQQ"
        self.e_phoff = e_phoff
        self.e_phentsize = e_phentsize
        self.segment_number = segment_number
        if header is not None:
            self._set_header(header)
            # self._repack_header()
        else:
            (
                self._p_type,
                self._p_flags,
                self._p_offset,
                self._p_vaddr,
                self._p_paddr,
                self._p_filesz,
                self._p_memsz,
                self._p_align
            ) = self._parse_header(data, segment_number)

        # Extract raw data
        self.data = data[self.p_offset:self.p_offset + self.p_filesz]

    def __str__(self):
        return f"{self.p_type} @ {hex(self.p_offset)}"

    def _set_header(self, header):
        self._p_type = header[0]
        self._p_flags = header[1]
        self._p_offset = header[2]
        self._p_vaddr = header[3]
        self._p_paddr = header[4]
        self._p_filesz = header[5]
        self._p_memsz = header[6]
        self._p_align = header[7]

    def _parse_header(self, data, segment_number):
        header = parse_header(data, segment_number, self.e_phentsize, self.e_phoff, self.hdr_struct)
        return (
            ProgramType(header[0]),
            header[1],
            header[2],
            header[3],
            header[4],
            header[5],
            header[6],
            header[7]
        )

    def _repack_header(self):
        offset = self.e_phoff + (self.segment_number * self.e_phentsize)
        repack_header(self._full_data, offset, self.e_phentsize, self.header, self.hdr_struct)


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

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        self._full_data = data
        self.hdr_struct = "IIQQQQIIQQ"
        self.e_shoff = e_shoff  # Section header offset
        self.e_shentsize = e_shentsize
        self.section_number = section_number
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
        repack_header(self._full_data, offset, self.e_shentsize, self.header, self.hdr_struct)


class Symbol:
    """ Symbol Header
    Elf64_Word      st_name;        /* Symbol name */
    unsigned char   st_info;        /* Type and Binding attributes */
    unsigned char   st_other;       /* Reserved */
    Elf64_Half      st_shndx;       /* Section table index */
    Elf64_Addr      st_value;       /* Symbol value */
    Elf64_Xword     st_size;        /* Size of object (e.g., common) */
    """

    @property
    def header(self):
        """ Gets the tuple containing the values within the header of the entity """
        return (
            self._st_name,
            self._st_info.get_value(),
            self._st_other,
            self._st_shndx,
            self._st_value,
            self._st_size
        )

    @property
    def st_name(self):
        """ Gets or sets the name of symbol """
        return self._st_name

    @st_name.setter
    def st_name(self, value):
        self._st_name = value
        self._repack_header()

    @property
    def st_info(self):
        """ Gets or sets the symbol type and binding attributes """
        return self._st_info

    @st_info.setter
    def st_info(self, value):
        self._st_info = value
        self._repack_header()

    @property
    def st_other(self):
        """ Gets or sets the reserved bit (must be zero)"""
        return self._st_other

    @st_other.setter
    def st_other(self, value):
        self._st_other = value
        self._repack_header()

    @property
    def st_shndx(self):
        """ Gets or sets the index of the section which the symbol is defined in (if available) """
        return self._st_shndx

    @st_shndx.setter
    def st_shndx(self, value):
        self._st_shndx = value
        self._repack_header()

    @property
    def st_value(self):
        """ Gets or sets the value of the symbol, either absolute or relocatable address """
        return self._st_value

    @st_value.setter
    def st_value(self, value):
        self._st_value = value
        self._repack_header()

    @property
    def st_size(self):
        """ Gets or sets the size of the symbol if available """
        return self._st_size

    @st_size.setter
    def st_size(self, value):
        self._st_size = value
        self._repack_header()

    def __init__(self, data, symbol_number, sh_offset, sh_entsize, header_names):
        self._full_data = data
        self.hdr_struct = "IbbHQQ"
        self.symbol_number = symbol_number
        self.sh_offset = sh_offset
        self.sh_entsize = sh_entsize
        (
            self._st_name,
            self._st_info,
            self._st_other,
            self._st_shndx,
            self._st_value,
            self._st_size
        ) = self._parse_header(data, symbol_number)

        # Get the name of the symbol
        if self.st_name > 0:
            self.symbol_name = parse_string_data(header_names.decode('utf-8'), self.st_name)
        else:
            self.symbol_name = None

    def __str__(self):
        return self.symbol_name

    def _parse_header(self, data, symbol_number):
        header = parse_header(data, symbol_number, self.sh_entsize, self.sh_offset, self.hdr_struct)
        return (
            header[0],  # st_name
            SymbolInfo(header[1]),  # st_info
            header[2] & 0x3,  # st_other
            header[3],  # st_shndx
            header[4],  # st_value
            header[5],  # st_size
        )

    def _repack_header(self):
        offset = self.sh_offset + (self.symbol_number * self.sh_entsize)
        repack_header(self._full_data, offset, self.sh_entsize, self.header, self.hdr_struct)


class SymbolInfo:
    def __init__(self, st_info):
        self.st_bind = SymbolBinding(st_info >> 4)
        self.st_type = SymbolType(st_info & 0xF)

    def get_value(self):
        return int(f"{self.st_bind.value:04b}{self.st_type.value:04b}", 2)


if __name__ == '__main__':
    with open('test/test', 'rb') as f:
        test = f.read()
    elffile = ELF(test)
    # elffile.append_segment(ProgramType.PT_LOAD, 7, bytearray(b'\xff' * 800))
    # elffile.append_segment(ProgramType.PT_LOAD, 7, bytearray())
    elffile.append_data_segment(bytearray(b'\xff' * 800))

    with open('test/packed', 'wb') as f:
        f.write(elffile.data)

    from elftools.elf.elffile import ELFFile

    p_elffile = ELFFile(open('test/packed', 'rb'))
    # p_segment = [x for x in p_elffile.iter_segments() if x.header.p_paddr == 15848][0]
    p_text = p_elffile.get_section_by_name('.text')
    p_add = p_elffile.get_section_by_name('.symtab').get_symbol_by_name('add')[0]
    print("Done")
