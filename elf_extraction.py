from elftools.elf.elffile import ELFFile
from capstone import *

elffile = ELFFile(open('test/test', 'rb'))
text = elffile.get_section_by_name('.text')

symtab = elffile.get_section_by_name('.symtab')
functions = [s for s in symtab.iter_symbols()
             if s['st_info']['type'] == 'STT_FUNC'
             and s['st_value'] >= text.header['sh_offset']]

md = Cs(CS_ARCH_X86, CS_MODE_64)
#for f in functions:
#    offset = f.entry['st_value'] - text.header['sh_offset']
#    print(f"FUNCTION: {f.name} @ {offset} @ {f.entry['st_value']}")
#    for x in md.disasm(text.data(), offset, count=f.entry['st_size']):
#        print("0x%x:\t%s\t%s" % (x.address, x.mnemonic, x.op_str))
#    print("\n\n\n\n\n")

i = 0
last_addr = 0
for dis in md.disasm(text.data(), 0, text.header['sh_size']):
    i = i + (dis.address - last_addr)
    new_function = [f for f in functions if f.entry['st_value'] - text.header['sh_offset'] == i]
    if len(new_function) > 0:
        print(f"\n\n\n\n{new_function[0].name}")
    print("0x%x:\t%s\t%s" % (dis.address + text.header['sh_offset'], dis.mnemonic, dis.op_str))
    last_addr = dis.address
