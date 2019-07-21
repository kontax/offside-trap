#!/usr/bin/env python

import json
import os
from shutil import copyfile
from subprocess import check_output, Popen, PIPE
from elf_packer import ELFPacker
from elf_parser import Function

FUNCTION_LIST = {
    './addr2line {} -e test 0x400000': [
        '-a',
        '-b elf64-x86-64',
        '-i',
        '-p',
        '-s',
        '-f',
        '-C',
        '-R',
        '-r',
        '-h',
        '-v',
    ],
    './cxxfilt {} fdsa': [
        '-_',
        '-n',
        '-p',
        '-i',
        '-R',
        '-r',
        '-t',
        '-s dlang',
        '-s java',
        '-h',
        '-v',
    ],
    './elfedit {} test': [
        '--output-type=rel',
        '--output-osabi=NSK',
        '--enable-x86-feature=ibt',
        '--disable-x86-feature=shstk',
        '-h',
        '-v',
    ],
    './nm-new {} test': [
        '-a',
        '-A',
        '-B',
        '--no-demangle',
        '--recurse-limit',
        '--no-recurse-limit',
        '-D',
        '--defined-only',
        '-f sysv',
        '-g',
        '-l',
        '-n',
        '-o',
        '-p',
        '-P',
        '-r',
        '-S',
        '-s',
        '--size-sort',
        '--special-syms',
        '--synthetic',
        '-u',
        '--with-symbol-versions',
        '-h',
        '-V',
    ],
    './objcopy {} test test.out': [
        '-I elf64-little',
        '-O elf64-little',
        '-F elf64-little',
        '--debugging',
        '-p',
        '-D',
        '-U',
        '-j .text',
        '-R .text',
        '-S',
        '-g',
        '--strip-dwo',
        '--strip-unneeded',
        '--only-keep-debug',
        '--extract-dwo',
        '--extract-symbol',
        '--keep-file-symbols',
        '--localize-hidden',
        '--weaken',
        '-w',
        '-x',
        '-X',
        '--set-start 0x4000',
        '--rename-section .text=.toad',
        '--long-section-names disable',
        '--change-leading-char',
        '--remove-leading-char',
        '--writable-text',
        '--readonly-text',
        '--pure',
        '--impure',
        '--prefix-symbols blah',
        '--prefix-sections blah',
        '--prefix-alloc-sections blah',
        '-M',
        '--no-merge-notes',
        '-v',
        '-V',
        '-h',
        '--info',
    ],
    './objdump {} test': [
        '-a',
        '-f',
        '-p',
        '-h',
        '-x',
        '-d',
        '-D',
        '-S',
        '-s',
        '-g',
        '-e',
        '-G',
        '-WL',
        '-Wp',
        '-WR',
        '-Wc',
        '-t',
        '-T',
        '-r',
        '-R',
        '-v',
        '-i',
        '-H',
    ],
    './readelf {} test': [
        '-a',
        '-h',
        '-l',
        '-S',
        '-g',
        '-t',
        '-e',
        '-s',
        '-n',
        '-r',
        '-u',
        '-d',
        '-V',
        '-A',
        '-c',
        '-x 3',
        '-p 3',
        '-R 3',
        '-wL',
        '-wF',
        '-ws',
        '-I',
        '-aW',
        '-H',
        '-v',
    ],
    './size {} test': [
        '-A',
        '-B',
        '-o',
        '-d',
        '-x',
        '-t',
        '--common',
        '--target=verilog',
        '-v',
    ],
    './strings {} test': [
        '-a',
        '-d',
        '-f',
        '-n 10',
        '-to',
        '-td',
        '-tx',
        '-w',
        '-o',
        '-T elf32-little',
        '-es',
        '-eS',
        '-eb',
        '-el',
        '-eB',
        '-eL',
        '-s a',
        '-h',
        '-v',
    ],
    './strip-new {} test': [
        '-I elf64-x86-64',
        '-O elf32-little',
        '-F elf64-x86-64',
        '-p',
        '-D',
        '-U',
        '-R .text',
        '-s',
        '-g',
        '--strip-dwo',
        '--strip-unneeded',
        '--only-keep-debug',
        '-M',
        '--no-merge-notes',
        '--keep-file-symbols',
        '-w',
        '-x',
        '-X',
        '-v',
        '-V',
        '-h',
        '--info',
        '-o strip-output',
    ]
}

os.chdir('test/bin/')
all_functions = {}
for prog in FUNCTION_LIST.keys():
    opts = FUNCTION_LIST[prog]
    bin_name = prog.split(' ')[0]
    bin_key = bin_name.split('/')[1]

    for opt in opts:
        copyfile('../source/test', './test')
        run_string = prog.format(opt).split(' ')
        print(run_string)
        check_output(run_string)

        ps = Popen(['gprof', '-b', '-p', bin_name], stdout=PIPE)
        awk = Popen(['awk', "{print $7}"], stdin=ps.stdout, stdout=PIPE)
        sed = Popen(["sed", "-r", "/^\s*$/d"], stdin=awk.stdout, stdout=PIPE)
        output = check_output(['grep', '-v', 'name'], stdin=sed.stdout)
        output = output.decode('utf-8')

        if bin_key not in all_functions:
            all_functions[bin_key] = set()

        all_functions[bin_key].update(output.split('\n'))

    all_functions[bin_key] = sorted(list(all_functions[bin_key]))

#output_file = json.dumps(all_functions)
#with open("all_functions.json", 'w') as f:
#    f.write(output_file)

for file in all_functions.keys():
    elf = ELFPacker(file)
    func_list = elf.list_functions()
    chosen_funcs = []
    for af in func_list:
        if af.name in all_functions[file]:
            chosen_funcs.append(af)
    elf.encrypt(50, chosen_funcs)

for prog in FUNCTION_LIST.keys():

