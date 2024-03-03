# ----------------------------------------------------------------------
# Sonix SNP70032 processor module
# Copyright (c) 2024 Ilya Kurdyukov
#
# Compatible with IDA 7.x and possibly later versions.

import sys
from ida_idp import *
from ida_ua import *
from ida_lines import *
from ida_problems import *
from ida_xref import *
from ida_idaapi import *
from ida_bytes import *

if sys.version_info.major < 3:
  range = xrange

# sign extend b low bits in x
def SIGNEXT(x, b):
    m = 1 << (b - 1)
    return (x & (m - 1)) - (x & m)

# values for insn_t.auxpref
AUX_IO = 4
AUX_ROM = 8

# ----------------------------------------------------------------------
class snp70032_processor_t(processor_t):
    """
    Processor module classes must derive from processor_t
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 70032

    # Processor features
    flag = PR_SEGS | PR_USE32 | PR_DEFSEG32 | PR_RNAMESOK | PRN_HEX

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    cnbits = 16

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    dnbits = 16

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ["snp70032"]

    # long processor names
    # No restriction on name lengthes.
    plnames = ["Sonix SNP70032"]

    # size of a segment register in bytes
    segreg_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 0, 0, 0)


    # only one assembler is supported
    assembler = {
        # flag
        "flag": ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF3 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        "uflag": 0,

        # Assembler name (displayed in menus)
        "name": "Sonix SNP70032 assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        # 'header': [".snp70032"],

        # org directive
        "origin": ".org",

        # end directive
        "end": ".end",

        # comment string (see also cmnt2)
        "cmnt": "#",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        "accsep": "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "dw",

        # byte directive
        'a_byte': "dw",

        # word directive
        'a_word': "dd",

        # remove if not allowed
        # 'a_dword': ".dword",

        # remove if not allowed
        # 'a_qword': ".qword",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "ds %s",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': ".",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "",

        # "extrn"  name keyword
        'a_extrn': ".extern",

        # "comm" (communal variable)
        "a_comdef": "",

        # "align" keyword
        "a_align": ".align",

        # Left and right braces used in complex expressions
        "lbrace": "(",
        "rbrace": ")",

        # %  mod     assembler time operation
        "a_mod": "%",

        # &  bit and assembler time operation
        "a_band": "&",

        # |  bit or  assembler time operation
        "a_bor": "|",

        # ^  bit xor assembler time operation
        "a_xor": "^",

        # ~  bit not assembler time operation
        "a_bnot": "~",

        # << shift left assembler time operation
        "a_shl": "<<",

        # >> shift right assembler time operation
        "a_shr": ">>",

        # size of type (format string) (optional)
        "a_sizeof_fmt": "size %s",

        'flag2': 0,

        # the include directive (format string) (optional)
        'a_include_fmt': '.include "%s"',
    }

    # ----------------------------------------------------------------------
    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[insn.itype]:
          return self.instruc[insn.itype]['cmt']

    # ----------------------------------------------------------------------

    maptbl_jcc = [
        'jeq', 'jne', 'jgt', 'jge',
        'jlt', 'jle', 'jav', 'jnav',
        'jac', 'jnac', 'jmr0s', 'jmr0ns',
        'jmv', 'jnmv', 'jixv', ''
    ]

    maptbl_arith = [ 'inc', 'dec', 'add', 'adc', 'sub', 'sbc' ]
    maptbl_bitwise = [ 'and', 'or', 'xor', 'not' ]
    maptbl_bit = ['bclr', 'bset', 'btog', 'btst']
    maptbl_mac = ['mul', 'mla', 'mls', '', 'fmul', 'fmla', 'fmls', '' ]
    maptbl_shift = [ '', 'sl', 'sra', 'srl' ]
    maptbl_stack = [ 'push', 'pop' ]

    maptbl_io = {
        0x00: 'SSF',
        0x01: 'SCR',
        0x02: 'Ix0',
        0x03: 'Ix1',
        0x04: 'Im00',
        0x05: 'Im01',
        0x06: 'Im02',
        0x07: 'Im03',
        0x08: 'Im10',
        0x09: 'Im11',
        0x0a: 'Im12',
        0x0b: 'Im13',
        0x0c: 'OPM_CONTROL',
        0x0d: 'RAMBk',
        0x0e: 'Ix0Bk',
        0x0f: 'Ix1Bk',
        0x10: 'T0',
        0x11: 'T1',
        0x12: 'T2',
        0x13: 'Iy0',
        0x14: 'Iy1',
        0x15: 'PCH',
        0x16: 'PCL',
        0x17: 'MMR',
        0x18: 'Sp',
        0x19: 'MR2',
        0x1a: 'Iy0Bk',
        0x1b: 'Iy1Bk',
        0x1c: 'Iy0BkRAM',
        0x1d: 'Iy1BkRAM',
        0x1e: 'Ix2',
        0x1f: 'Iy2',
        0x20: 'INTEN',
        0x21: 'INTRQ',
        0x22: 'INTPR',
        0x23: 'INTCR',
        0x24: 'PCR1',
        0x25: 'OPM_CTRL1',
        0x26: 'ADC_FIFOSTATUS',
        0x28: 'ADC_DATA',
        0x29: 'WDT',
        0x2a: 'ADC_SET1',
        0x2b: 'ADC_SET2',
        0x2c: 'ImxL',
        0x2d: 'ImxC',
        0x2e: 'ImyL',
        0x2f: 'ImyC',
        0x30: 'P0WKUPEN',
        0x31: 'P1WKUPEN',
        0x32: 'INTEN2',
        0x33: 'INTRQ2',
        0x34: 'INTPR2',
        0x35: 'INTCR2',
        0x36: 'IBx',
        0x37: 'ILx',
        0x38: 'IBy',
        0x39: 'ILy',
        0x3a: 'IOSW',
        0x3b: 'SP1',
        0x3c: 'IOSW2',
        0x3d: 'EVENT',
        0x3e: 'ShIdx',
        0x3f: 'ShV2',
        0x40: 'T1CNTV',
        0x45: 'T0CNT',
        0x46: 'T1CNT',
        0x47: 'T0CNTV',
        0x48: 'INTEC',
        0x49: 'DAC_SET1',
        0x4a: 'DAC_SET2',
        0x4b: 'DAC_FIFOSTATUS',
        0x4c: 'T2CNT',
        0x4d: 'EVENT0CNT',
        0x4e: 'EVENT1CNT',
        0x4f: 'EVENT2CNT',
        0x50: 'I2SCTRL',
        0x51: 'PWM0',
        0x52: 'PWM1',
        0x53: 'PWM2',
        0x54: 'PWM3',
        0x55: 'DAOL',
        0x56: 'DAOR',
        0x57: 'SPIDADA0',
        0x58: 'SPIDADA1',
        0x59: 'SPIDADA2',
        0x5a: 'SPIDADA3',
        0x5b: 'SPIDADA4',
        0x5c: 'SPIDADA5',
        0x5d: 'SPICTRL',
        0x5e: 'SPICSC',
        0x5f: 'SPITRANSFER',
        0x61: 'SPIBR',
        0x62: 'MSPSTAT',
        0x63: 'MSPM1',
        0x64: 'MSPM2',
        0x65: 'MSPBUF',
        0x66: 'MSPADR',
        0x67: 'CHIP_ID',
        0x68: 'P0En',
        0x69: 'P0',
        0x6a: 'P0M',
        0x6b: 'P0PH',
        0x6c: 'P1En',
        0x6d: 'P1',
        0x6e: 'P1M',
        0x6f: 'P1PH',
        0x74: 'P3En',
        0x75: 'P3',
        0x76: 'P3M',
        0x77: 'P3PH',
        0x78: 'P4En',
        0x79: 'P4',
        0x7a: 'P4M',
        0x7b: 'P4PH',
        0x7c: 'SYSCONF',
        0x7d: 'ADP',
        0x7e: 'ADM',
        0x7f: 'ADR'
    }

    def notify_ana(self, insn):
        """
        Decodes an instruction into 'insn'.
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        opc = get_16bit(insn.ea) & 0xffff
        insn.size += 1

        # Call
        if opc & 0x8000 == 0:
            insn.itype = self.name2icode['call']
            addr = opc & 0x7fff
            insn.Op1.type = o_near
            insn.Op1.addr = addr

        # Jump
        elif opc & 0xf000 == 0x8000:
            insn.itype = self.name2icode['jmp']
            addr = insn.ea + 1 + SIGNEXT(opc, 12)
            insn.Op1.type = o_near
            insn.Op1.addr = addr & 0xffffff

        # Jump Condition
        elif opc & 0xf000 == 0x9000:
            opc2 = opc >> 8 & 15
            if opc2 == 15:
                return 0
            insn.itype = self.maptbl_jcc[opc2]
            addr = insn.ea + 1 + SIGNEXT(opc, 8)
            insn.Op1.type = o_near
            insn.Op1.addr = addr & 0xffffff

        # RW SRAM (direct)
        elif opc & 0xe000 == 0xa000:
            insn.itype = self.name2icode['mov']
            reg = opc >> 8 & 7
            addr = (opc >> 3 & 0x100) | (opc & 0xff)
            if opc & 0x1000:
                insn.Op1.type = o_reg
                insn.Op1.reg = reg
                insn.Op2.type = o_mem
                insn.Op2.addr = addr
            else:
                insn.Op1.type = o_mem
                insn.Op1.addr = addr
                insn.Op2.type = o_reg
                insn.Op2.reg = reg

        # AU(2)
        elif opc & 0xf880 == 0xc800:
            reg1 = opc >> 5 & 3
            reg2 = ((opc & 3) ^ 2) + 2
            opc2 = opc >> 2 & 7
            if opc2 >= 6:
               reg1, reg2 = reg2, reg1
               opc2 -= 2

            insn.itype = self.maptbl_arith[opc2]
            insn.Op1.type = o_displ
            insn.Op1.reg = (opc >> 8 & 1) + 8
            insn.auxpref = opc >> 9 & 3
            insn.Op2.type = o_reg
            insn.Op2.reg = reg1
            if opc2 >= 2:
                insn.Op3.type = o_reg
                insn.Op3.reg = reg2

        # LU(1)
        elif opc & 0xf884 == 0xc880:
            reg1 = opc >> 5 & 3 # Xop
            reg2 = ((opc & 3) ^ 2) + 2 # Yop
            opc2 = opc >> 3 & 3
            insn.itype = self.maptbl_bitwise[opc2]
            insn.Op1.type = o_reg
            insn.Op1.reg = opc >> 8 & 7
            insn.Op2.type = o_reg
            insn.Op2.reg = reg1
            if opc2 < 3:
                insn.Op3.type = o_reg
                insn.Op3.reg = reg2

        # LU(2)
        elif opc & 0xf884 == 0xc884:
            opc2 = opc >> 3 & 3
            insn.itype = self.maptbl_bit[opc2]
            insn.Op1.type = o_reg
            insn.Op1.reg = (opc >> 8 & 1) + 2 # R0, R1
            insn.Op2.type = o_reg
            insn.Op2.reg = ((opc & 3) ^ 2) + 2 # Yop
            insn.Op3.type = o_imm
            insn.Op3.value = (opc >> 7 & 0xc) | (opc >> 5 & 3)

        # Load Immediate
        elif opc & 0xe000 == 0xc000:
            reg = opc >> 8 & 7
            # X0, X1, R0, R1, Y0, Y1, Ix0, Ix1
            if reg >= 6:
                reg += 2

            opc2 = opc >> 11 & 3
            if opc2 == 0:
                insn.itype = self.name2icode['movh']
            elif opc2 == 2:
                insn.itype = self.name2icode['movl']
            elif opc2 == 3:
                insn.itype = self.name2icode['mov']
            else:
                return 0

            insn.Op1.type = o_reg
            insn.Op1.reg = reg
            insn.Op2.type = o_imm
            insn.Op2.value = opc & 0xff

        # RW SRAM (indirect)
        elif opc & 0xf883 == 0xe000:
            insn.itype = self.name2icode['mov']
            reg1 = opc >> 8 & 7
            reg2 = (opc >> 2 & 3) + 8
            insn.auxpref = opc >> 4 & 3
            if opc & 0x40:
                insn.Op1.type = o_reg
                insn.Op1.reg = reg1
                insn.Op2.type = o_displ
                insn.Op2.reg = reg2
            else:
                insn.Op1.type = o_displ
                insn.Op1.reg = reg2
                insn.Op2.type = o_reg
                insn.Op2.reg = reg1

        # Load ROM (indirect)
        elif opc & 0xf8c3 == 0xe041:
            insn.itype = self.name2icode['mov']
            reg1 = opc >> 8 & 7
            reg2 = (opc >> 2 & 3) + 8
            insn.auxpref = (opc >> 4 & 3) | AUX_ROM
            insn.Op1.type = o_reg
            insn.Op1.reg = reg1
            insn.Op2.type = o_displ
            insn.Op2.reg = reg2

        # Shift index
        elif opc & 0xf8c7 == 0xe042:
            opc2 = opc >> 3 & 3
            if opc == 0:
                return 0
            insn.itype = self.maptbl_shift[opc2]
            insn.Op1.type = o_reg
            insn.Op1.reg = (opc >> 5 & 1) + 2 # R0, R1
            insn.Op2.type = o_reg
            insn.Op2.reg = opc >> 8 & 7
            insn.Op3.type = o_reg
            insn.Op3.reg = self.ireg_ShIdx

        # I/O
        elif opc & 0xf880 == 0xe080:
            insn.itype = self.name2icode['mov']
            reg = opc >> 8 & 3
            insn.auxpref = AUX_IO
            if opc & 0x0400:
                insn.Op1.type = o_reg
                insn.Op1.reg = reg
                insn.Op2.type = o_imm
                insn.Op2.value = opc & 0x7f
            else:
                insn.Op1.type = o_imm
                insn.Op1.value = opc & 0x7f
                insn.Op2.type = o_reg
                insn.Op2.reg = reg

        # AU(1)
        elif opc & 0xf800 == 0xe800:
            reg1 = opc >> 5 & 7
            reg2 = ((opc & 3) ^ 2) + 2
            opc2 = opc >> 2 & 7
            if opc2 >= 6:
               reg1, reg2 = reg2, reg1
               opc2 -= 2

            insn.itype = self.maptbl_arith[opc2]
            insn.Op1.type = o_reg
            insn.Op1.reg = opc >> 8 & 7
            insn.Op2.type = o_reg
            insn.Op2.reg = reg1
            if opc2 >= 2:
                insn.Op3.type = o_reg
                insn.Op3.reg = reg2

        # MAC
        elif opc & 0xf800 == 0xf000:
            opc2 = opc >> 8 & 7
            if opc2 & 3 == 3:
                return 0
            insn.itype = self.maptbl_mac[opc2]
            insn.Op1.type = o_reg
            insn.Op1.reg = opc >> 1 & 1 # X0, X1
            insn.Op2.type = o_reg
            insn.Op2.reg = (opc & 1) + 4 # Y0, Y1
            if opc & 0x80:
                insn.itype += 6
                insn.Op3.type = o_reg
                # X0, X1, Y0, Y1
                insn.Op3.reg = ((opc >> 2 & 3) + 2) & 5
                insn.Op4.type = o_displ
                insn.Op4.reg = 8 + (opc >> 6 & 1) # Ix0, Ix1
                insn.auxpref = opc >> 4 & 3

        # Reg Move
        elif opc & 0xff03 == 0xf800:
            insn.itype = self.name2icode['mov']
            insn.Op1.type = o_reg
            insn.Op1.reg = opc >> 2 & 7
            insn.Op2.type = o_reg
            insn.Op2.reg = opc >> 5 & 7

        # Push/Pop
        elif opc & 0xff1e == 0xf802:
            insn.itype = self.maptbl_stack[opc & 1]
            insn.Op1.type = o_reg
            insn.Op1.reg = opc >> 5 & 7

        # Shift
        elif opc & 0xfe00 == 0xfa00:
            opc2 = opc >> 3 & 3
            insn.itype = self.maptbl_shift[opc2]
            insn.Op1.type = o_reg
            insn.Op1.reg = (opc >> 5 & 1) + 2 # R0, R1
            insn.Op2.type = o_reg
            insn.Op2.reg = opc >> 5 & 7
            insn.Op3.type = o_imm
            insn.Op3.value = (opc & 7) + 1

        # Push/Pop I/O
        elif opc & 0xff80 == 0xfc80:
            insn.itype = self.maptbl_stack[opc >> 6 & 1]
            insn.Op1.type = o_imm
            insn.Op1.value = opc & 0x3f
            insn.auxpref = AUX_IO

        # Call Far Far
        elif opc & 0xff00 == 0xfd00:
            insn.itype = self.name2icode['callff']
            addr = get_16bit(insn.ea + 1) & 0xffff
            insn.size += 1
            addr |= (opc & 0xff) << 16
            insn.Op1.type = o_near
            insn.Op1.addr = addr

        # Jump Far Far
        elif opc & 0xff00 == 0xfe00:
            insn.itype = self.name2icode['jmpff']
            addr = get_16bit(insn.ea + 1) & 0xffff
            insn.size += 1
            addr |= (opc & 0xff) << 16
            insn.Op1.type = o_near
            insn.Op1.addr = addr

        elif opc & 0xff80 == 0xfc00:
            if opc & 0x40 == 0:
                insn.itype = self.name2icode['do0']
            else:
                insn.itype = self.name2icode['do1']
            insn.Op1.type = o_imm
            insn.Op1.value = opc & 0x3f

        elif opc == 0xfffc:
            insn.itype = self.name2icode['loop0']
        elif opc == 0xfffe:
            insn.itype = self.name2icode['loop1']

        elif opc == 0xff40:
            insn.itype = self.name2icode['ret']
        elif opc == 0xff41:
            insn.itype = self.name2icode['reti']
        elif opc == 0xff42:
            insn.itype = self.name2icode['retff']
        elif opc == 0xfffd:
            insn.itype = self.name2icode['icec']
        elif opc == 0xffff:
            insn.itype = self.name2icode['nop']
        elif opc == 0xff01:
            insn.itype = self.name2icode['disSPSW']
        elif opc == 0xff00:
            insn.itype = self.name2icode['enSPSW']

        else:
            return 0

        return insn.size

    # ----------------------------------------------------------------------
    def handle_operand(self, insn, op, dref_flag):
        if op.type == o_near:
            if insn.get_canon_feature() & CF_CALL:
                insn.add_cref(op.addr, 0, fl_CN)
            else:
                insn.add_cref(op.addr, 0, fl_JN)

    def notify_emu(self, insn):
        Feature = insn.get_canon_feature()

        if Feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, dr_R)
        if Feature & CF_CHG1:
            self.handle_operand(insn, insn.Op1, dr_W)
        if Feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, dr_R)
        if Feature & CF_USE3:
            self.handle_operand(insn, insn.Op2, dr_R)
        if Feature & CF_USE4:
            self.handle_operand(insn, insn.Op2, dr_R)
        if Feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

        flow = Feature & CF_STOP == 0
        if flow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return True

    # ----------------------------------------------------------------------
    def notify_out_operand(self, ctx, op):
        optype = op.type

        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif optype == o_imm:
            if ctx.insn.auxpref & AUX_IO:
                ctx.out_line('IO')
                ctx.out_symbol('(')
                if op.value in self.maptbl_io:
                    ctx.out_line(self.maptbl_io[op.value])
                else:
                    ctx.out_value(op, OOFW_32 | OOF_SIGNED)
                ctx.out_symbol(')')
            else:
                ctx.out_value(op, OOFW_32 | OOF_SIGNED)

        elif optype == o_near:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_long(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        elif optype == o_mem:
            ctx.out_line('DM')
            ctx.out_symbol('(')
            ctx.out_long(op.addr, 16)
            ctx.out_symbol(')')
        elif optype == o_displ:
            if ctx.insn.auxpref & AUX_ROM:
                ctx.out_line('ROM')
            ctx.out_symbol('(')
            ctx.out_register(self.reg_names[op.reg])
            if ctx.insn.auxpref & 3:
                ctx.out_symbol(',')
                ctx.out_char(' ')
                if ctx.insn.auxpref & 2:
                   if ctx.insn.auxpref & 1:
                       ctx.out_symbol('-')
                   ctx.out_char('1')
                else:
                   ctx.out_char('m')
            ctx.out_symbol(')')
        else:
            return False

        return True

    # ----------------------------------------------------------------------
    def out_mnem(self, ctx):
        ctx.out_mnem(8, "")
        return 1

    # ----------------------------------------------------------------------
    def notify_out_insn(self, ctx):
        ctx.out_mnemonic()

        if ctx.insn.Op1.type != o_void:
            ctx.out_one_operand(0)
        for i in range(1, 4):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    # ----------------------------------------------------------------------

    # Array of instructions
    instruc = [
        {'name': '', 'feature': 0, 'cmt': 'bad opcode'},

        {'name': 'call',   'feature': CF_USE1 | CF_CALL },
        {'name': 'jmp',    'feature': CF_USE1 | CF_JUMP | CF_STOP, 'cmt': 'unconditional jump'},

        {'name': 'jeq',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if equal'},
        {'name': 'jne',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if not equal'},
        {'name': 'jgt',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if greater than'},
        {'name': 'jge',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if greater than or equal'},
        {'name': 'jlt',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if less than'},
        {'name': 'jle',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if less than or equal'},
        {'name': 'jav',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if ALU overflow'},
        {'name': 'jnav',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if not ALU overflow'},

        {'name': 'jac',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if ALU carry'},
        {'name': 'jnac',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if not ALU carry'},
        {'name': 'jmr0s',  'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if MR0 signed'},
        {'name': 'jmr0ns', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if MR0 not signed'},
        {'name': 'jmv',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if MAC overflow'},
        {'name': 'jnmv',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if not MAC overflow'},
        {'name': 'jixv',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if index overflow'},

        {'name': 'mov',    'feature': CF_CHG1 | CF_USE2, 'cmt': 'move'},
        {'name': 'movl',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'low byte load'},
        {'name': 'movh',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'high byte load'},

        {'name': 'inc',    'feature': CF_CHG1 | CF_USE2, 'cmt': 'increment'},
        {'name': 'dec',    'feature': CF_CHG1 | CF_USE2, 'cmt': 'decrement'},
        {'name': 'add',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'add'},
        {'name': 'adc',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'add with carry'},
        {'name': 'sub',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'subtract'},
        {'name': 'sbc',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'subtract with borrow'},

        {'name': 'and',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'or',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'xor',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'not',    'feature': CF_CHG1 | CF_USE2 },

        {'name': 'sl',     'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'shift left'},
        {'name': 'sra',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'shift right arithmetic'},
        {'name': 'srl',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'shift right logical'},

        {'name': 'bclr',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'bit clear'},
        {'name': 'bset',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'bit set'},
        {'name': 'btog',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'bit toggle'},
        {'name': 'btst',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'bit test'},

        {'name': 'mul',    'feature': CF_USE1 | CF_USE2, 'cmt': 'multiply'},
        {'name': 'mla',    'feature': CF_USE1 | CF_USE2, 'cmt': 'multiply accumulate'},
        {'name': 'mls',    'feature': CF_USE1 | CF_USE2, 'cmt': 'multiply subtract'},
        {'name': 'fmul',   'feature': CF_USE1 | CF_USE2, 'cmt': 'fractional multiply'},
        {'name': 'fmla',   'feature': CF_USE1 | CF_USE2, 'cmt': 'fractional multiply accumulate'},
        {'name': 'fmls',   'feature': CF_USE1 | CF_USE2, 'cmt': 'fractional multiply subtract'},
        {'name': 'mul_ld', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'multiply and load'},
        {'name': 'mla_ld', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'multiply accumulate and load'},
        {'name': 'mls_ld', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'multiply subtract and load'},
        {'name': 'fmul_ld', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fractional multiply and load'},
        {'name': 'fmla_ld', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fractional multiply accumulate and load'},
        {'name': 'fmls_ld', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, 'cmt': 'fractional multiply subtract and load'},

        {'name': 'push',   'feature': CF_USE1 },
        {'name': 'pop',    'feature': CF_USE1 },

        {'name': 'callff', 'feature': CF_USE1 | CF_CALL, 'cmt': 'call far far'},
        {'name': 'jmpff',  'feature': CF_USE1 | CF_JUMP | CF_STOP, 'cmt': 'jump far far'},

        {'name': 'do0',    'feature': CF_USE1 },
        {'name': 'do1',    'feature': CF_USE1 },
        {'name': 'loop0',  'feature': 0 },
        {'name': 'loop1',  'feature': 0 },

        {'name': 'ret',    'feature': CF_STOP, 'cmt': 'return from call'},
        {'name': 'reti',   'feature': CF_STOP, 'cmt': 'return from interrupt'},
        {'name': 'retff',  'feature': CF_STOP, 'cmt': 'return from call far far'},

        {'name': 'icec',   'feature': 0, 'cmt': 'ICE call'},
        {'name': 'nop',    'feature': 0, 'cmt': 'no operation'},
        {'name': 'disSPSW', 'feature': 0, 'cmt': 'clear SCR.SPSW'},
        {'name': 'enSPSW', 'feature': 0, 'cmt': 'enable SCR.SPSW'}
    ]

    # icode of the first instruction
    instruc_start = 0

    def maptbl_icode(self, tab):
        for i, s in enumerate(tab):
            tab[i] = self.name2icode[s]

    def init_instructions(self):

        for i in range(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        self.name2icode = {}
        for i, x in enumerate(self.instruc):
            self.name2icode[x['name']] = i

        # icode of the last instruction + 1
        self.instruc_end = len(self.instruc)

        self.maptbl_icode(self.maptbl_jcc)
        self.maptbl_icode(self.maptbl_arith)
        self.maptbl_icode(self.maptbl_bitwise)
        self.maptbl_icode(self.maptbl_bit)
        self.maptbl_icode(self.maptbl_mac)
        self.maptbl_icode(self.maptbl_shift)
        self.maptbl_icode(self.maptbl_stack)

    # ----------------------------------------------------------------------

    # Registers definition
    reg_names = [
        'x0', 'x1', 'r0', 'r1', 'y0', 'y1', 'mr0', 'mr1'
        'Ix0', 'Ix1', 'Iy0', 'Iy1',
        'ShIdx',

        # Fake segment registers
        "CS", "DS"
    ]

    def init_registers(self):
        # number of CS register
        self.reg_code_sreg = self.reg_names.index("CS")

        # number of DS register
        self.reg_data_sreg = self.reg_names.index("DS")

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.reg_code_sreg
        self.reg_last_sreg  = self.reg_data_sreg

    # ----------------------------------------------------------------------
    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from processor_t
def PROCESSOR_ENTRY():
    return snp70032_processor_t()
