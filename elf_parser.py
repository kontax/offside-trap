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


# class ELFIdent:
#
#     @property
#     def el_mag(self):
#         """ Magic bytes """
#         return self._el_mag
#
#     @el_mag.setter
#     def el_mag(self, value):
#         self._el_mag = value
#
#     """ e_ident containing identification details of the ELF file """
#     def __init__(self, header):
#         (
#             self._el_mag,           # Magic bytes
#             self.el_class,          # x86 or x64
#             self.el_data,           # Big or little endian
#             self.el_version,        # ELF version (always 1)
#             self.el_osabi,          # OS Application Binary Interface
#             self.el_abiversion,     # ABI version
#             self.el_pad,            # Padding
#             self.el_ident           # Size of ident
#         ) = self._parse_header(header, 16, "4sbbbbb6sb")
#         assert(self.el_mag == b"\x7fELF")
#
#     @staticmethod
#     def _parse_header(data, header_size, hdr_struct):
#         header = unpack(hdr_struct, data[:header_size])
#         return (
#             header[0],
#             ELFClass(header[1]),
#             ELFData(header[2]),
#             header[3],
#             ELFOSABI(header[4]),
#             header[5],
#             header[6],
#             header[7]
#         )

class ELFIdent:
    """ e_ident containing identification details of the ELF file """
    def __init__(self, header):
        self.data = header
        self.el_mag = header[0:4]
        assert(self.el_mag == b"\x7fELF")
        self.el_class = ELFClass(header[4])
        self.el_data = ELFData(header[5])
        self.el_version = header[6]
        self.el_osabi = ELFOSABI(header[7])
        self.el_abiversion = header[8]
        self.el_pad = header[9:15]
        self.el_nident = header[15]


def repack_header(data, hdr_offset, hdr_size, hdr, hdr_struct):
    data[hdr_offset:hdr_size] = pack(hdr_struct, *hdr)


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

        print("DONE")

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

    def __init__(self, data, segment_number, e_phoff, e_phentsize):
        self._full_data = data
        self.hdr_struct = "IIQQQQQQ"
        self.e_phoff = e_phoff
        self.e_phentsize = e_phentsize
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
        self.data = data[self.p_offset:self.p_offset+self.p_filesz]

    def __str__(self):
        return f"{self.p_type} @ {hex(self.p_offset)}"

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
        repack_header(self._full_data, self.p_offset, self.p_filesz, self.header, self.hdr_struct)


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
        self.data = data[self.sh_offset:self.sh_offset+self.sh_size]

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
        repack_header(self._full_data, self.sh_offset, self.sh_size, self.header, self.hdr_struct)


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
        self.hdr_struct = "IssHQQ"
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
            ord(header[2]) & 0x3,  # st_other
            header[3],  # st_shndx
            header[4],  # st_value
            header[5],  # st_size
        )

    def _repack_header(self):
        repack_header(self._full_data, self.sh_offset*self.symbol_number, self.st_size, self.header, self.hdr_struct)


class SymbolInfo:
    def __init__(self, st_info):
        self.st_bind = SymbolBinding(ord(st_info) >> 4)
        self.st_type = SymbolType(ord(st_info) & 0xF)

    def get_value(self):
        return bytes(int(f"{self.st_bind.value:04b}{self.st_type.value:04b}", 2))


if __name__ == '__main__':
    with open('test/test', 'rb') as f:
        test = f.read()
    elffile = ELF(test)

    elffile.e_phnum = 15  # Was 11
    elffile.e_shnum = 28  # Was 29

    text = elffile.sections[13]
    text.sh_name = 149  # was 148
    text.sh_type = SectionType(9)  # was SHT_PROGBITS

    segment = elffile.segments[5]
    segment.p_type = ProgramType(7)  # was PT_LOAD
    segment.p_flags = 7  # was 6

    symbol = elffile.symbols[46]
    #symbol.st_info = SymbolInfo(b'\x11')  # was STB_WEAK and STT_NOTYPE
    symbol.st_shndx = 26  # was 23

    with open('test/packed', 'wb') as f:
        f.write(elffile.data)

    from elftools.elf.elffile import ELFFile
    elffile = ELFFile(open('test/packed', 'rb'))
    print("Done")
