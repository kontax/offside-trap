from elf.data import StructEntity
from elf.enums import *
from elf.helpers import parse_struct, _check_range_overlaps
from elf.section import create_dynamic_table, parse_notes_data


class SegmentFactory:
    @staticmethod
    def create_segment(data, segment_number, e_phoff, e_phentsize, header=None):
        hdr_struct = "IIQQQQQQ"
        program_header = parse_struct(data, segment_number, e_phoff, e_phentsize, hdr_struct)
        segment_type = ProgramType(program_header[0])
        if segment_type == ProgramType.PT_DYNAMIC:
            return DynamicSegment(data, segment_number, e_phoff, e_phentsize, header)
        elif segment_type == ProgramType.PT_NOTE:
            return NoteSegment(data, segment_number, e_phoff, e_phentsize, header)
        else:
            segment = Segment(data, segment_number, e_phoff, e_phentsize, header)
            return segment


class SegmentHeader(StructEntity):
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
    def p_type(self):
        """ Gets or sets the type of segment """
        return ProgramType(self._get_value(0))

    @p_type.setter
    def p_type(self, value):
        self._set_value(0, value.value)

    @property
    def p_flags(self):
        """ Gets or sets the flags of the segment """
        return self._get_value(1)

    @p_flags.setter
    def p_flags(self, value):
        self._set_value(1, value)

    @property
    def p_offset(self):
        """ Gets or sets the offset of the program header within the file """
        return self._get_value(2)

    @p_offset.setter
    def p_offset(self, value):
        self._set_value(2, value)

    @property
    def p_vaddr(self):
        """ Gets or sets the virtual address of the segment within memory """
        return self._get_value(3)

    @p_vaddr.setter
    def p_vaddr(self, value):
        self._set_value(3, value)

    @property
    def p_paddr(self):
        """ Gets or sets some reserved bytes in memory """
        return self._get_value(4)

    @p_paddr.setter
    def p_paddr(self, value):
        self._set_value(4, value)

    @property
    def p_filesz(self):
        """ Gets or sets the size of the segment within the file """
        return self._get_value(5)

    @p_filesz.setter
    def p_filesz(self, value):
        self._set_value(5, value)

    @property
    def p_memsz(self):
        """ Gets or sets the size of the segment within the memory """
        return self._get_value(6)

    @p_memsz.setter
    def p_memsz(self, value):
        self._set_value(6, value)

    @property
    def p_align(self):
        """ Gets or sets the alignment of the segment - must be a power of 2, with p_offset and p_vaddr
        congruent modulo the alignment """
        return self._get_value(7)

    @p_align.setter
    def p_align(self, value):
        self._set_value(7, value)

    def __init__(self, data, segment_number, e_phoff, e_phentsize):
        hdr_struct = "IIQQQQQQ"
        super().__init__(data, segment_number, e_phoff, e_phentsize, hdr_struct)


class Segment:
    @property
    def sections(self):
        """ Gets the collection of sections contained within the segment"""
        return self._sections

    @property
    def live_data(self):
        start = self.header.p_offset
        end = self.header.p_offset + self.header.p_filesz
        return self._full_data[start:end]

    def __init__(self, data, segment_number, e_phoff, e_phentsize, header=None):
        self._full_data = data
        self.hdr_struct = "IIQQQQQQ"
        self.e_phoff = e_phoff
        self.e_phentsize = e_phentsize
        self.segment_number = segment_number
        self._sections = []
        self.header = SegmentHeader(data, segment_number, e_phoff, e_phentsize)
        if header is not None:
            self._set_header_values(header)

        # Extract raw data
        self.data = data[self.header.p_offset:self.header.p_offset + self.header.p_filesz]

    def __str__(self):
        return f"{self.header.p_type} @ {hex(self.header.p_offset)}"

    def load_sections(self, sections):
        """
        Parses a list of sections and adds them to the local collection if they are contained within
        the address range of the current segment.

        :param sections: The full collection of sections to check.
        """
        relevant_sections = [x for x in sections
                             if x.header.sh_offset >= self.header.p_offset
                             and x.header.sh_offset + x.header.sh_size <= self.header.p_offset + self.header.p_filesz]
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
        gap_start = self.header.p_offset + self.header.p_filesz  # The end of the current segment
        gap_end = closest_segment.header.p_offset  # The start of the next segment

        for segment in segments:

            # Don't need to check the current segments
            if segment is self or segment is closest_segment:
                continue

            segment_end = segment.header.p_offset + segment.header.p_filesz

            # Check segments within the gap
            if gap_start <= segment.header.p_offset <= gap_end \
                    or gap_start <= segment_end <= gap_end:
                return True

            # Check segments overlapping the gap entirely
            if segment.header.p_offset <= gap_start and segment_end >= gap_end:
                return True

        return False

    def shift(self, start_offset, end_offset, shift_by, validate=True):
        hdr = self.header
        overlap = _check_range_overlaps(start_offset, end_offset, hdr.p_offset, hdr.p_offset + hdr.p_filesz)
        if overlap is None:
            return

        # Move the start only if it's after the start offset
        if overlap == Overlap.RIGHT or overlap == Overlap.INNER:
            hdr.p_offset += shift_by
            hdr.p_paddr += shift_by
            hdr.p_vaddr += shift_by

            # Ensure the data still matches, and update the data snapshot
            if validate:
                assert(self.data == self.live_data)
            self.data = self._full_data[hdr.p_offset:hdr.p_offset + hdr.p_filesz]

        # Otherwise increase the size
        if overlap == Overlap.LEFT or overlap == Overlap.OVER:
            hdr.p_filesz += shift_by
            hdr.p_memsz += shift_by

            # Ensure the start and end values match what they did previously, and update the snapshot
            if validate:
                assert (self.data[:shift_by] == self.live_data[:shift_by])
                assert (self.data[-shift_by:] == self.live_data[-shift_by:])
            self.data = self._full_data[hdr.p_offset:hdr.p_offset + hdr.p_filesz]

    def _set_header_values(self, header):
        """ Sets all the current segments header values to the values in the specified header
        :param header: The header with the values to clone
        """
        self.header.p_type = ProgramType(header[0])
        self.header.p_flags = header[1]
        self.header.p_offset = header[2]
        self.header.p_vaddr = header[3]
        self.header.p_paddr = header[4]
        self.header.p_filesz = header[5]
        self.header.p_memsz = header[6]
        self.header.p_align = header[7]


class DynamicSegment(Segment):
    """ Contains the dynamic linking tables used to store details on dynamically loaded libraries. """
    def __init__(self, data, segment_number, e_phoff, e_phentsize, header=None):
        super().__init__(data, segment_number, e_phoff, e_phentsize, header)
        self.dynamic_table = create_dynamic_table(self._full_data, self.data, self.header.p_offset)


class NoteSegment(Segment):
    def __init__(self, data, segment_number, e_phoff, e_phentsize, header=None):
        super().__init__(data, segment_number, e_phoff, e_phentsize, header)
        self.notes = parse_notes_data(self._full_data, self.data, self.header.p_offset)
