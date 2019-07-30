from elf_enums import SymbolBinding, SymbolType
from elf_parser import parse_string_data, parse_header, repack_header


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
        return f"{self.symbol_name} @ 0x{self.st_value:0x}: {self.st_info}"

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

    def __str__(self):
        return f"[{self.st_type.name} @ {self.st_bind.name}]"
