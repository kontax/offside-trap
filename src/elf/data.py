from struct import unpack

from elf.enums import DynamicTag, GnuNoteType
from elf.helpers import repack


class DynamicTableEntry:
    """ Dynamic Table Entry
    Elf64_Sxword        d_tag   /* Identifies the type of dynamic table entry */
    union {
        Elf64_Xword     d_val   /* Integer value */
        Elf64_Addr      d_ptr   /* Link-time program virtual address */
    } d_un
    """
    @property
    def data(self):
        """ Gets the tuple containing the values within the data of the entity """
        return (
            self.d_tag.value,
            self.d_un
        )

    @property
    def d_tag(self):
        """ Gets or sets the type of dynamic table entry """
        return self._d_tag

    @d_tag.setter
    def d_tag(self, value):
        self._d_tag = value
        self._repack()

    @property
    def d_un(self):
        """ Gets or sets either a value or dynamic pointer, dependent on the type of entry """
        return self._d_un

    @d_un.setter
    def d_un(self, value):
        self._d_un = value
        self._repack()

    def __init__(self, data, d_tag, d_un, offset, struct):
        """ Initializes a new single entry for the dynamic table, containing the type and value.
        TODO: Split out d_ptr and d_val for their respective types

        :param data: The full data of the binary
        :param d_tag: The tag containing the type of entry - this value determines whether d_un contains a val or ptr
        :param d_un: A union containing either a value or pointer, depending on the value of d_tag
        :param offset: The offset in bytes of the entry within the binary
        :param struct: The format of the binary data to be packed/unpacked
        """
        self._full_data = data
        self._d_tag = DynamicTag(d_tag)
        self._d_un = d_un
        self.offset = offset
        self.struct = struct

    def __str__(self):
        return f"{self.d_tag}"

    def _repack(self):
        repack(self._full_data, self.offset, 16, self.data, self.struct)


class Note:

    @property
    def namesz(self):
        """ Gets the size in bytes of the name of the note """
        return self._namesz

    @property
    def descsz(self):
        """ Gets the size in bytes of the notes description """
        return self._descsz

    @property
    def name(self):
        """ Gets the name of the note """
        return self._name

    @property
    def desc(self):
        """ Gets the notes description """
        return self._desc

    def __init__(self, namesz, descsz, note_type, name, desc):
        self._namesz = namesz
        self._descsz = descsz
        self._type = GnuNoteType(note_type)
        self._name = name

        if name == 'GNU' and self._type == GnuNoteType.NT_GNU_ABI_TAG:
            ver = unpack('IIII', desc)
            self._desc = f"Linux ABI: {ver[1]}.{ver[2]}.{ver[3]}"
        elif name == 'GNU' and self._type == GnuNoteType.NT_GNU_BUILD_ID:
            build_id = ''.join(f"{x:02x}" for x in desc)
            self._desc = f"Build ID: {build_id}"
        else:
            self._desc = ''.join(f"{x:02x}" for x in desc)

    def __str__(self):
        return f"[{self.name}] {self.desc}"