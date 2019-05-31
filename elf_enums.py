from enum import Enum


class ELFDataType(Enum):
    """ The size in bytes of each data-type within the ELF structure """
    Elf64_Addr = 8  # Unsigned program address
    Elf64_Off = 8  # Unsigned file offset
    Elf64_Half = 2  # Unsigned medium integer
    Elf64_Word = 4  # Unsigned integer
    Elf64_Sword = 4  # Signed integer
    Elf64_Xword = 8  # Unsigned long integer
    Elf64_Sxword = 8  # Signed long integer
    unsigned_char = 0  # Unsigned small integer


""" ELF HEADER """


class ELFClass(Enum):
    """ Whether it's a 32 or 64 bit ELF file """
    ELFCLASSNONE = 0
    ELFCLASS32 = 1  # 32-bit objects
    ELFCLASS64 = 2  # 64-bit objects
    ELFCLASSNUM = 3


class ELFData(Enum):
    """ Whether the ELF file is in bit or little endian format """
    ELFDATANONE = 0
    ELFDATA2LSB = 1  # Little endian
    ELFDATA2MSB = 2  # Big endian
    ELFDATANUM = 3


class ELFFileType(Enum):
    """ The type of file the ELF is """
    ET_NONE = 0  # No file type
    ET_REL = 1  # Relocatable object file
    ET_EXEC = 2  # Executable file
    ET_DYN = 3  # Shared object file
    ET_CORE = 4  # Core file
    ET_NUM = 5
    ET_LOOS = 0xFE00  # Environment - specific use
    ET_HIOS = 0xFEFF
    ET_LOPROC = 0xFF00  # Processor - specific use
    ET_HIPROC = 0xFFFF


class ELFOSABI(Enum):
    ELFOSABI_SYSV = 0
    ELFOSABI_HPUX = 1  # Hewlett-Packard HP-UX
    ELFOSABI_NETBSD = 2  # NetBSD
    ELFOSABI_LINUX = 3  # Linux
    ELFOSABI_UNKNOWN4 = 4
    ELFOSABI_UNKNOWN5 = 5
    ELFOSABI_SOLARIS = 6  # Sun Solaris
    ELFOSABI_AIX = 7  # AIX
    ELFOSABI_IRIX = 8  # IRIX
    ELFOSABI_FREEBSD = 9  # FreeBSD
    ELFOSABI_TRU64 = 10  # Compaq TRU64 UNIX
    ELFOSABI_MODESTO = 11  # Novell Modesto
    ELFOSABI_OPENBSD = 12  # Open BSD
    ELFOSABI_OPENVMS = 13  # Open VMS
    ELFOSABI_NSK = 14  # Hewlett-Packard Non-Stop Kernel
    ELFOSABI_AROS = 15  # Amiga Research OS
    ELFOSABI_ARM = 97  # ARM
    ELFOSABI_STANDALONE = 255  # standalone (embedded) application


class ELFMachine(Enum):
    """ The architecture the ELF file runs on """
    EM_NONE = 0  # e_machine
    EM_M32 = 1  # AT&T WE 32100
    EM_SPARC = 2  # Sun SPARC
    EM_386 = 3  # Intel 80386
    EM_68K = 4  # Motorola 68000
    EM_88K = 5  # Motorola 88000
    EM_486 = 6  # Intel 80486
    EM_860 = 7  # Intel i860
    EM_MIPS = 8  # MIPS RS3000 Big-Endian
    EM_S370 = 9  # IBM System/370 Processor
    EM_MIPS_RS3_LE = 10  # MIPS RS3000 Little-Endian
    EM_RS6000 = 11  # RS6000
    EM_UNKNOWN12 = 12
    EM_UNKNOWN13 = 13
    EM_UNKNOWN14 = 14
    EM_PA_RISC = 15  # PA-RISC
    EM_PARISC = EM_PA_RISC        # Alias: GNU compatibility
    EM_nCUBE = 16  # nCUBE
    EM_VPP500 = 17  # Fujitsu VPP500
    EM_SPARC32PLUS = 18  # Sun SPARC 32+
    EM_960 = 19  # Intel 80960
    EM_PPC = 20  # PowerPC
    EM_PPC64 = 21  # 64-bit PowerPC
    EM_S390 = 22  # IBM System/390 Processor
    EM_UNKNOWN22 = EM_S390                # Alias: Older published name
    EM_UNKNOWN23 = 23
    EM_UNKNOWN24 = 24
    EM_UNKNOWN25 = 25
    EM_UNKNOWN26 = 26
    EM_UNKNOWN27 = 27
    EM_UNKNOWN28 = 28
    EM_UNKNOWN29 = 29
    EM_UNKNOWN30 = 30
    EM_UNKNOWN31 = 31
    EM_UNKNOWN32 = 32
    EM_UNKNOWN33 = 33
    EM_UNKNOWN34 = 34
    EM_UNKNOWN35 = 35
    EM_V800 = 36  # NEX V800
    EM_FR20 = 37  # Fujitsu FR20
    EM_RH32 = 38  # TRW RH-32
    EM_RCE = 39  # Motorola RCE
    EM_ARM = 40  # Advanced RISC Marchines ARM
    EM_ALPHA = 41  # Digital Alpha
    EM_SH = 42  # Hitachi SH
    EM_SPARCV9 = 43  # Sun SPARC V9 (64-bit)
    EM_TRICORE = 44  # Siemens Tricore embedded processor
    EM_ARC = 45  # Argonaut RISC Core,
    EM_H8_300 = 46  # Hitachi H8/300
    EM_H8_300H = 47  # Hitachi H8/300H
    EM_H8S = 48  # Hitachi H8S
    EM_H8_500 = 49  # Hitachi H8/500
    EM_IA_64 = 50  # Intel IA64
    EM_MIPS_X = 51  # Stanford MIPS-X
    EM_COLDFIRE = 52  # Motorola ColdFire
    EM_68HC12 = 53  # Motorola M68HC12
    EM_MMA = 54  # Fujitsu MMA Mulimedia Accelerator
    EM_PCP = 55  # Siemens PCP
    EM_NCPU = 56  # Sony nCPU embedded RISC processor
    EM_NDR1 = 57  # Denso NDR1 microprocessor
    EM_STARCORE = 58  # Motorola Star*Core processor
    EM_ME16 = 59  # Toyota ME16 processor
    EM_ST100 = 60  # STMicroelectronics ST100 processor
    EM_TINYJ = 61  # Advanced Logic Corp. TinyJ
    EM_AMD64 = 62  # AMDs x86-64 architecture
    EM_X86_64 = EM_AMD64          # (compatibility)
    EM_PDSP = 63  # Sony DSP Processor
    EM_UNKNOWN64 = 64
    EM_UNKNOWN65 = 65
    EM_FX66 = 66  # Siemens FX66 microcontroller
    EM_ST9PLUS = 67  # STMicroelectronics ST9+8/16 bit
    EM_ST7 = 68  # STMicroelectronics ST7 8-bit
    EM_68HC16 = 69  # Motorola MC68HC16 Microcontroller
    EM_68HC11 = 70  # Motorola MC68HC11 Microcontroller
    EM_68HC08 = 71  # Motorola MC68HC08 Microcontroller
    EM_68HC05 = 72  # Motorola MC68HC05 Microcontroller
    EM_SVX = 73  # Silicon Graphics SVx
    EM_ST19 = 74  # STMicroelectronics ST19 8-bit
    EM_VAX = 75  # Digital VAX
    EM_CRIS = 76  # Axis Communications 32-bit
    EM_JAVELIN = 77  # Infineon Technologies 32-bit
    EM_FIREPATH = 78  # Element 14 64-bit DSP Processor
    EM_ZSP = 79  # LSI Logic 16-bit DSP Processor
    EM_MMIX = 80  # Donald Knuth's educational
    EM_HUANY = 81  # Harvard University
    EM_PRISM = 82  # SiTera Prism
    EM_AVR = 83  # Atmel AVR 8-bit microcontroller
    EM_FR30 = 84  # Fujitsu FR30
    EM_D10V = 85  # Mitsubishi D10V
    EM_D30V = 86  # Mitsubishi D30V
    EM_V850 = 87  # NEC v850
    EM_M32R = 88  # Mitsubishi M32R
    EM_MN10300 = 89  # Matsushita MN10300
    EM_MN10200 = 90  # Matsushita MN10200
    EM_PJ = 91  # picoJava
    EM_OPENRISC = 92  # OpenRISC 32-bit embedded processor
    EM_ARC_A5 = 93  # ARC Cores Tangent-A5
    EM_XTENSA = 94  # Tensilica Xtensa architecture
    EM_NUM = 95


""" PROGRAM HEADER """


class ProgramType(Enum):
    PT_NULL = 0   # p_type
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7
    PT_NUM = 8
    PT_LOOS = 0x60000000  # OS specific range
    PT_SUNW_UNWIND = 0x6464e550  # amd64 UNWIND program header
    PT_LOSUNW = 0x6ffffffa
    PT_SUNWSTACK = 0x6ffffffb  # describes the stack segment
    PT_SUNWDTRACE = 0x6ffffffc  # private
    PT_SUNWCAP = 0x6ffffffd  # hard/soft capabilities segment
    PT_HIOS = 0x6fffffff
    PT_LOPROC = 0x70000000  # processor specific range
    PT_HIPROC = 0x7fffffff


""" SECTION HEADER """


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
    SHT_UNKNOWN12 = 12
    SHT_UNKNOWN13 = 13
    SHT_INIT_ARRAY = 14
    SHT_FINI_ARRAY = 15
    SHT_PREINIT_ARRAY = 16
    SHT_GROUP = 17
    SHT_SYMTAB_SHNDX = 18
    SHT_NUM = 19
    SHT_LOOS = 0x60000000  # OS specific range
    SHT_LOSUNW = 0x6ffffff1
    SHT_SUNW_symsort = 0x6ffffff1
    SHT_SUNW_tlssort = 0x6ffffff2
    SHT_SUNW_LDYNSYM = 0x6ffffff3
    SHT_SUNW_dof = 0x6ffffff4
    SHT_SUNW_cap = 0x6ffffff5
    SHT_SUNW_SIGNATURE = 0x6ffffff6
    SHT_SUNW_ANNOTATE = 0x6ffffff7
    SHT_SUNW_DEBUGSTR = 0x6ffffff8
    SHT_SUNW_DEBUG = 0x6ffffff9
    SHT_SUNW_move = 0x6ffffffa
    SHT_SUNW_COMDAT = 0x6ffffffb
    SHT_SUNW_syminfo = 0x6ffffffc
    SHT_SUNW_verdef = 0x6ffffffd
    SHT_SUNW_verneed = 0x6ffffffe
    SHT_SUNW_versym = 0x6fffffff
    SHT_HISUNW = 0x6fffffff
    SHT_HIOS = 0x6fffffff
    SHT_GNU_verdef = 0x6ffffffd
    SHT_GNU_verneed = 0x6ffffffe
    SHT_GNU_versym = 0x6fffffff
    SHT_LOPROC = 0x70000000  # processor specific range
    SHT_HIPROC = 0x7fffffff
    SHT_LOUSER = 0x80000000
    SHT_HIUSER = 0xffffffff


""" SYMBOLS """


class SymbolBinding(Enum):
    STB_LOCAL = 0  # Not visible outside the object file
    STB_GLOBAL = 1  # Global symbol, visible to all object files
    STB_WEAK = 2  # Global scope, but with lower precedence than global symbols
    STB_LOOS = 10  # Environment-specific use
    STB_HIOS = 12
    STB_LOPROC = 13  # Processor-specific use
    STB_HIPROC = 15


class SymbolType(Enum):
    STT_NOTYPE = 0  # No type specified (eg. an absolute symbol)
    STT_OBJECT = 1  # Data object
    STT_FUNC = 2  # Function entry point
    STT_SECTION = 3  # Symbol is associated with a section
    STT_FILE = 4  # Source file associated with the object file
    STT_LOOS = 10  # Environment-specific use
    STT_HIOS = 12
    STT_LOPROC = 13  # Processor-specific use
    STT_HIPROC = 15
