from struct import unpack

from elf_enums import ProgramType, DynamicTag
from elf_parser import parse_header, repack_header


class SegmentFactory:
    @staticmethod
    def create_segment(data, segment_number, e_phoff, e_phentsize, header=None):
        segment = Segment(data, segment_number, e_phoff, e_phentsize, header)
        if segment.p_type == ProgramType.PT_DYNAMIC:
            return DynamicSegment(data, segment_number, e_phoff, e_phentsize, header)
        else:
            return segment


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

    @property
    def sections(self):
        """ Gets the collection of sections contained within the segment"""
        return self._sections

    def __init__(self, data, segment_number, e_phoff, e_phentsize, header=None):
        self._full_data = data
        self.hdr_struct = "IIQQQQQQ"
        self.e_phoff = e_phoff
        self.e_phentsize = e_phentsize
        self.segment_number = segment_number
        self._sections = []
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

    def load_sections(self, sections):
        """
        Parses a list of sections and adds them to the local collection if they are contained within
        the address range of the current segment.

        :param sections: The full collection of sections to check.
        """
        relevant_sections = [x for x in sections
                             if x.sh_offset >= self.p_offset
                             and x.sh_offset + x.sh_size <= self.p_offset + self.p_filesz]
        self._sections.extend(relevant_sections)

    def is_segment_gap_overlapped(self, closest_segment, segments):
        """
        Checks whether a gap between this segment and the next closest one is overlapped by any other segment in
        a list. This covers situations whereby a segment either completely overlaps the gap, ends in the middle,
        or starts in the middle.

        :param closest_segment: The segment next to this with a gap of null bytes between them.
        :param segments: A list of segments to check through
        :return: True if there is an overlapping segment, otherwise false.
        """
        gap_start = self.p_offset + self.p_filesz  # The end of the current segment
        gap_end = closest_segment.p_offset  # The start of the next segment

        for segment in segments:

            # Don't need to check the current segments
            if segment is self or segment is closest_segment:
                continue

            segment_end = segment.p_offset + segment.p_filesz

            # Check segments within the gap
            if gap_start <= segment.p_offset <= gap_end \
                    or gap_start <= segment_end <= gap_end:
                return True

            # Check segments overlapping the gap entirely
            if segment.p_offset <= gap_start and segment_end >= gap_end:
                return True

        return False

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


class DynamicSegment(Segment):
    def __init__(self, data, segment_number, e_phoff, e_phentsize, header=None):
        super().__init__(data, segment_number, e_phoff, e_phentsize, header)
        self.dynamic_table = self._create_dynamic_table(self.data)

    def _create_dynamic_table(self, data):
        i = 0
        table = []
        struct = 'QQ'
        offset = self.p_offset
        while i < len(data):
            d_tag, d_un = unpack(struct, data[i:i + 16])
            table.append(DynamicTableEntry(self._full_data, d_tag, d_un, offset+i, struct))
            i += 16

        return table


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
        self._full_data = data
        self._d_tag = DynamicTag(d_tag)
        self._d_un = d_un
        self.offset = offset
        self.struct = struct

    def __str__(self):
        return f"{self.d_tag}"

    def _repack(self):
        repack_header(self._full_data, self.offset, 16, self.data, self.struct)
