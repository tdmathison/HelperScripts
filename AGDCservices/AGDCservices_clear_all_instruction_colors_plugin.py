# AGDCservices_clear_all_instruction_colors_plugin.py
#
# IDA Pro 7.6 - IDAPython conversion of AGDCservices script
# This is a rough conversion of the following script that was built for Ghidra
# https://github.com/AGDCservices/Ghidra-Scripts/blob/master/Clear_All_Instruction_Colors.py
#
# Travis Mathison | github.com/tdmathison

import idaapi
import idautils

PLUGIN_COMMENT = "Clears all colors applied to instructions in program"
PLUGIN_HELP = ""
PLUGIN_NAME = "AGDCservices - Clear All Instruction Colors"
PLUGIN_WANTED_HOTKEY = ""

class clear_highlight_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_WANTED_HOTKEY

    COLOR_DEFAULT = 0xFFFFFF

    def init(self):
        try:
            return idaapi.PLUGIN_OK
        except Exception as err:
            idaapi.msg("Exception during init: %s\n" % str(err))
        
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        try:
            for ea in idautils.Heads():
                idaapi.set_item_color(ea, self.COLOR_DEFAULT)

        except Exception as err:
            idaapi.msg("Exception during run: %s\n" % str(err))
            raise

    def term(self):
        pass

def PLUGIN_ENTRY():
    return clear_highlight_plugin_t()