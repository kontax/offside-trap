from elf.data import StructEntity
from elf.enums import SymbolBinding, SymbolType
from elf.helpers import parse_string_data


def parse_symbols_data(full_data, offset, total_size, entity_size, header_names=None):
    symbols = []
    for i in range(int(total_size / entity_size)):
        symbols.append(Symbol(full_data, i, offset, entity_size, header_names))

    return symbols


class SymbolInfo(StructEntity):
    @property
    def st_bind(self):
        return SymbolBinding(self._get_value(1) >> 4)

    @st_bind.setter
    def st_bind(self, value):
        self._set_value(1, (value.value << 4) | (self.st_type.value & 0xF))

    @property
    def st_type(self):
        return SymbolType(self._get_value(1) & 0xF)

    @st_type.setter
    def st_type(self, value):
        self._set_value(1, (self.st_bind.value << 4) | (value.value & 0xF))

    def get_value(self):
        return int(f"{self.st_bind.value:04b}{self.st_type.value:04b}", 2)

    def __str__(self):
        return f"[{self.st_type.name} @ {self.st_bind.name}]"


class SymbolHeader(StructEntity):
    """ Symbol Header
    Elf64_Word      st_name;        /* Symbol name */
    unsigned char   st_info;        /* Type and Binding attributes */
    unsigned char   st_other;       /* Reserved */
    Elf64_Half      st_shndx;       /* Section table index */
    Elf64_Addr      st_value;       /* Symbol value */
    Elf64_Xword     st_size;        /* Size of object (e.g., common) */
    """
    @property
    def st_name(self):
        """ Gets or sets the name of symbol """
        return self._get_value(0)

    @st_name.setter
    def st_name(self, value):
        self._set_value(0, value)

    @property
    def st_info(self):
        """ Gets the symbol type and binding attributes """
        return self._st_info

    @property
    def st_other(self):
        """ Gets the reserved bit (must be zero)"""
        return self._get_value(2) & 0x3

    @property
    def st_shndx(self):
        """ Gets or sets the index of the section which the symbol is defined in (if available) """
        return self._get_value(3)

    @st_shndx.setter
    def st_shndx(self, value):
        self._set_value(3, value)

    @property
    def st_value(self):
        """ Gets or sets the value of the symbol, either absolute or relocatable address """
        return self._get_value(4)

    @st_value.setter
    def st_value(self, value):
        self._set_value(4, value)

    @property
    def st_size(self):
        """ Gets or sets the size of the symbol if available """
        return self._get_value(5)

    @st_size.setter
    def st_size(self, value):
        self._set_value(5, value)

    def __init__(self, data, symbol_number, sh_offset, sh_entsize):
        hdr_struct = "IBBHQQ"
        super().__init__(data, symbol_number, sh_offset, sh_entsize, hdr_struct)
        self._st_info = SymbolInfo(data, symbol_number, sh_offset, sh_entsize, hdr_struct)


class Symbol:

    def __init__(self, data, symbol_number, sh_offset, sh_entsize, header_names):
        self._full_data = data
        self.header = SymbolHeader(data, symbol_number, sh_offset, sh_entsize)

        # Get the name of the symbol
        if self.header.st_name > 0 and header_names is not None:
            self.symbol_name = parse_string_data(header_names.decode('utf-8'), self.header.st_name)
        else:
            self.symbol_name = None

    def __str__(self):
        return f"{self.symbol_name} @ 0x{self.header.st_value:0x}: {self.header.st_info}"

    def populate_names(self, strtab):
        """ Populates the symbol with the text value it points to from the linked section.

        :param strtab: The strtab section linked to the symtab section this symbol is part of
        """
        if self.header.st_name > 0 and strtab is not None:
            self.symbol_name = parse_string_data(strtab.data.decode('utf-8'), self.header.st_name)
