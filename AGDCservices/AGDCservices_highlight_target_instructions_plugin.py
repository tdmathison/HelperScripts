# AGDCservices_highlight_target_instructions_plugin.py
#
# IDA Pro 7.6 - IDAPython conversion of AGDCservices script
# This is a rough conversion of the following script that was built for Ghidra
# https://github.com/AGDCservices/Ghidra-Scripts/blob/master/Highlight_Target_Instructions.py
#
# Travis Mathison | github.com/tdmathison

import idautils
import idaapi
import ida_allins
import ida_bytes
import idc
import ida_ua

PLUGIN_COMMENT = "Highlights target instructions using custom colors for easy identification"
PLUGIN_HELP = ""
PLUGIN_NAME = "AGDCservices - Highlight Target Instructions"
PLUGIN_WANTED_HOTKEY = ""

# get the IDA version number
ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (ida_major > 6)
ex_addmenu_item_ctx = None 

class highlight_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_WANTED_HOTKEY

    COLOR_DEFAULT = 0xFFFFFF
    COLOR_CALL = 0xFFDCDC
    COLOR_POINTER = 0xC8F0FF
    COLOR_CRYPTO = 0xF5CDFF
    COLOR_STRING_OPERATION = 0xB4E6AA

    def init(self):
        try:
            return idaapi.PLUGIN_OK
        except Exception as err:
            idaapi.msg("Exception during init: %s\n" % str(err))
        
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        try:
            for ea in idautils.Heads():
                #print(idc.print_operand(ea, 0))
                mnem = idc.print_insn_mnem(ea)
                
                # color call instructions
                if mnem == 'call':
                    idaapi.set_item_color(ea, self.COLOR_CALL)
                    continue

                # color lea instructions
                if mnem == 'lea':
                    idaapi.set_item_color(ea, self.COLOR_POINTER)
                    continue

                # color suspected crypto instructions
                # xor that does not zero out the register
                if mnem == 'xor' and (idc.print_operand(ea, 0) != idc.print_operand(ea, 1)):
                    idaapi.set_item_color(ea, self.COLOR_CRYPTO)
                    continue

                # common RC4 instructions
                if mnem == 'cmp' and idc.get_operand_type(ea,0) == ida_ua.o_reg and idc.print_operand(ea, 1) == '0x100':
                    idaapi.set_item_color(ea, self.COLOR_CRYPTO)
                    continue

                # misc math operations
                mathInstrList = ['sar', 'sal', 'shr', 'shl', 'ror', 'rol', 'idiv', 'div', 'imul', 'mul', 'not']
                if mnem in mathInstrList:
                    idaapi.set_item_color(ea, self.COLOR_CRYPTO)
                    continue

                # color string operations
                # skip instructions that start with 'c' to exclude conditional moves, e.g. cmovs
                if (mnem.startswith('c') == False) and (mnem.endswith('x') == False) and \
                    (('scas' in mnem) or ('movs' in mnem) or ('stos' in mnem)):
                    idaapi.set_item_color(ea, self.COLOR_STRING_OPERATION)
                    continue

        except Exception as err:
            idaapi.msg("Exception during run: %s\n" % str(err))
            raise

    def term(self):
        pass

def PLUGIN_ENTRY():
    return highlight_plugin_t()