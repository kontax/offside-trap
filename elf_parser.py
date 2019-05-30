from enum import Enum
from struct import unpack


class ELFDataType(Enum):
    Elf64_Addr = 8  # Unsigned program address
    Elf64_Off = 8  # Unsigned file offset
    Elf64_Half = 2  # Unsigned medium integer
    Elf64_Word = 4  # Unsigned integer
    Elf64_Sword = 4  # Signed integer
    Elf64_Xword = 8  # Unsigned long integer
    Elf64_Sxword = 8  # Signed long integer
    unsigned_char = 1  # Unsigned small integer


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
        self.header_size = 64
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
        ) = self._parse_header(data)

        # Extract the segments
        for i in range(self.e_phnum):
            self.segments.append(Segment(data, i, self.e_phoff, self.e_phentsize))

        # Extract the Sections
        for i in range(self.e_shnum):
            self.sections.append(Section(data, i, self.e_shoff, self.e_shentsize))

    @staticmethod
    def _parse_header(data):
        return unpack("16sHHIQQQIHHHHHH", data[:64])


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
        ) = self.parse_headers(data, segment_number)

    def parse_headers(self, data, segment_number):

        # e_shentsize is the header size for the section
        offset = segment_number * self.e_phentsize
        start_offset = self.e_phoff + offset
        end_offset = start_offset + self.e_phentsize

        # Extract the header data from the
        segment_data = data[start_offset:end_offset]
        header = unpack("IIQQQQIIQQ", segment_data)
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

    def __init__(self, data, section_number, e_shoff, e_shentsize):
        self.e_shoff = e_shoff # Section header offset
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
        ) = self.parse_header(data, section_number)

    def parse_header(self, data, section_number):

        # e_shentsize is the header size for the section
        offset = section_number * self.e_shentsize
        start_offset = self.e_shoff + offset
        end_offset = start_offset + self.e_shentsize

        # Extract the header data from the
        segment_data = data[start_offset:end_offset]
        header = unpack("IIQQQQIIQQ", segment_data)
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
        ) = parse_header(data)
