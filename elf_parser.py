from enum import Enum
from struct import unpack


class ELFDataType(Enum):
    """ The size in bytes of each data-type within the ELF structure """
    Elf64_Addr = 8  # Unsigned program address
    Elf64_Off = 8  # Unsigned file offset
    Elf64_Half = 2  # Unsigned medium integer
    Elf64_Word = 4  # Unsigned integer
    Elf64_Sword = 4  # Signed integer
    Elf64_Xword = 8  # Unsigned long integer
    Elf64_Sxword = 8  # Signed long integer
    unsigned_char = 1  # Unsigned small integer


class ELFClass(Enum):
    """ Whether it's a 32 or 64 bit ELF file """
    ELFCLASS32 = 1  # 32-bit objects
    ELFCLASS64 = 2  # 64-bit objects


class DataEncodings(Enum):
    """ Whether the ELF file is in bit or little endian format """
    ELFDATA2LSB = 1  # Little endian
    ELFDATA2MSB = 2  # Big endian


class OSABI(Enum):
    """ The Application Binary Interface of the Operating System being used """
    ELFOSABI_SYSV = 0  # SystemV ABI
    ELFOSABI_HPUX = 1  # HP-UX
    ELFOSABI_STANDALONE = 255  # Standalone / Embedded


class ELFFileType(Enum):
    """ The type of file the ELF is """
    ET_NONE = 0  # No file type
    ET_REL = 1  # Relocatable object file
    ET_EXEC = 2  # Executable file
    ET_DYN = 3  # Shared object file
    ET_CORE = 4  # Core file
    ET_LOOS = 0xFE00  # Environment - specific use
    ET_HIOS = 0xFEFF
    ET_LOPROC = 0xFF00  # Processor - specific use
    ET_HIPROC = 0xFFFF


class SectionType(Enum):
    SHT_NULL = 0  # Marks an unused section header
    SHT_PROGBITS = 1  # Contains information defined by the program
    SHT_SYMTAB = 2  # Contains a linker symbol table
    SHT_STRTAB = 3  # Contains a string table
    SHT_RELA = 4  # Contains “Rela” type relocation entries
    SHT_HASH = 5  # Contains a symbol hash table
    SHT_DYNAMIC = 6  # Contains dynamic linking tables
    SHT_NOTE = 7  # Contains note information
    SHT_NOBITS = 8  # Contains uninitialized space; does not occupy any space in the file
    SHT_REL = 9  # Contains “Rel” type relocation entries
    SHT_SHLIB = 10  # Reserved
    SHT_DYNSYM = 11  # Contains a dynamic loader symbol table
    SHT_LOOS = 0x60000000  # Environment - specific use
    SHT_HIOS = 0x6FFFFFFF
    SHT_LOPROC = 0x70000000  # Processor - specific use
    SHT_HIPROC = 0x7FFFFFFF


class ELFIdent:
    """ e_ident containing identification details of the ELF file """
    def __init__(self, header):
        self.el_mag = header[0:4]
        assert(self.el_mag == b"\x7fELF")
        self.el_class = ELFClass(header[4])
        self.el_data = DataEncodings(header[5])
        self.el_version = header[6]
        self.el_osabi = OSABI(header[7])
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

    def __init__(self, data):
        self.header_size = 64  # TODO: This is contained in the header as e_ehsize
        self.segments = []
        self.sections = []
        (
            self.e_ident,
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx
        ) = self._parse_header(data, self.header_size)
        self.data = data

        # Pull the data containing the segment names initially
        section_names_data = Section(data, self.e_shstrndx, self.e_shoff, self.e_shentsize).data

        # Extract the segments
        for i in range(self.e_phnum):
            self.segments.append(Segment(data, i, self.e_phoff, self.e_phentsize))

        # Extract the Sections
        for i in range(self.e_shnum):
            self.sections.append(Section(data, i, self.e_shoff, self.e_shentsize, section_names_data))

        print("DONE")

    @staticmethod
    def _parse_header(data, header_size):
        header = unpack("16sHHIQQQIHHHHHH", data[:header_size])
        return (
            ELFIdent(header[0]),  # e_ident
            ELFFileType(header[1]),  # e_type
            header[2],  # e_machine
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

    def __init__(self, data, segment_number, e_phoff, e_phentsize):
        self.e_phoff = e_phoff
        self.e_phentsize = e_phentsize
        (
            self.p_type,
            self.p_flags,
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
            self.p_align
        ) = self._parse_header(data, segment_number)

        # Extract raw data
        self.data = data[self.p_offset:self.p_offset+self.p_filesz]

    def _parse_header(self, data, segment_number):

        # e_shentsize is the header size for the section
        offset = segment_number * self.e_phentsize
        start_offset = self.e_phoff + offset
        end_offset = start_offset + self.e_phentsize

        # Extract the header data from the
        segment_data = data[start_offset:end_offset]
        header = unpack("IIQQQQQQ", segment_data)
        return header


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

    def __init__(self, data, section_number, e_shoff, e_shentsize, header_names=None):
        self.e_shoff = e_shoff  # Section header offset
        self.e_shentsize = e_shentsize
        (
            self.sh_name,
            self.sh_type,
            self.sh_flags,
            self.sh_addr,
            self.sh_offset,
            self.sh_size,
            self.sh_link,
            self.sh_info,
            self.sh_addralign,
            self.sh_entsize
        ) = self._parse_header(data, section_number)

        # Get the name of the section
        if header_names is not None:
            self.section_name = self._get_c_string(header_names.decode('utf-8'), self.sh_name)

        # Extract raw data
        self.data = data[self.sh_offset:self.sh_offset+self.sh_size]

    def __str__(self):
        return f"{self.section_name} @ {hex(self.sh_offset)}"

    def _parse_header(self, data, section_number):

        # e_shentsize is the header size for the section
        offset = section_number * self.e_shentsize
        start_offset = self.e_shoff + offset
        end_offset = start_offset + self.e_shentsize

        # Extract the header data from the
        segment_data = data[start_offset:end_offset]
        header = unpack("IIQQQQIIQQ", segment_data)
        return (
            header[0],
            header[1],  # TODO: This should be a SectionType
            header[2],
            header[3],
            header[4],
            header[5],
            header[6],
            header[7],
            header[8],
            header[9],
        )

    @staticmethod
    def _get_c_string(data, offset):
        out = []
        i = offset
        while data[i] != "\x00":
            out.append(data[i])
            i += 1

        return ''.join(out)


class Symbol:
    """ Symbol Header
    Elf64_Word      st_name;        /* Symbol name */
    unsigned char   st_info;        /* Type and Binding attributes */
    unsigned char   st_other;       /* Reserved */
    Elf64_Half      st_shndx;       /* Section table index */
    Elf64_Addr      st_value;       /* Symbol value */
    Elf64_Xword     st_size;        /* Size of object (e.g., common) */
    """

    def __init__(self, data):
        (
            self.st_name,
            self.st_info,
            self.st_other,
            self.st_shndx,
            self.st_value,
            self.st_size
        ) = _parse_header(data)


if __name__ == '__main__':
    with open('test/test', 'rb') as f:
        test = f.read()
    elffile = ELF(test)
