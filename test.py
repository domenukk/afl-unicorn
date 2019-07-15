#!/usr/bin/env python3
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *

def main():
    cs = Cs(CS_ARCH_X86, CS_MODE_64) # type: capstone.Cs
    uc = Uc(UC_ARCH_X86, UC_MODE_64) # type: unicorn.Uc

    cmpxchange16b = b"\xf0\x49\x0f\xc7\x0c\x24" + b"\xff\x25\x00\x00\x00\x00"
    insn_pos = 0xFFFFFFFF00b9a6000

    uc.mem_map(insn_pos, 4096)
    uc.mem_write(insn_pos, cmpxchange16b)
    try:
        uc.emu_start(insn_pos, len(cmpxchange16b), count=1)
        print("Done with emulation.")
        return 0
    except Exception as ex:
        print("Error {}: ".format(ex), *(list(cs.disasm_lite(bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RIP), 10)), 0))[0]))

        return -1

if __name__ == "__main__":
    main()
