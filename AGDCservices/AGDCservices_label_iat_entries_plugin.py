# AGDCservices_label_iat_entries_plugin.py
#
# IDA Pro 7.6 - IDAPython conversion of AGDCservices script
# This is a rough conversion of the following script that was built for Ghidra
# https://github.com/AGDCservices/Ghidra-Scripts/blob/master/Label_Dynamically_Resolved_Iat_Entries.py
#
# Travis Mathison | github.com/tdmathison

import idaapi
import idautils
import idc
import ida_ua
import os

from PyQt5 import QtCore, QtGui, QtWidgets

PLUGIN_COMMENT = "Find dynamically resolved IAT locations and apply labels from input file"
PLUGIN_HELP = ""
PLUGIN_NAME = "AGDCservices - Apply IAT locations from input file"
PLUGIN_WANTED_HOTKEY = ""

def Get_Dynamically_Resolved_Iat_Addresses():
    iatSet = set()
    for ea in idautils.Heads():
        mnem = idc.print_insn_mnem(ea)
        if mnem == 'call':
            operandRef = idc.print_operand(ea, 0)
            if len(operandRef) != 0:
                if operandRef.lower().startswith( ('dat_', 'byte_', 'word_', 'dword_', 'qword_') ):
                    iatSet.add(operandRef)
    return list(iatSet)

def Label_Dynamically_Resolved_Iat_Addresses(iatList, labeledIatDumpFileName):
    with open(labeledIatDumpFileName, 'r') as fp:
        labeledIatList = fp.read().splitlines()
    
    imageBase = idaapi.get_imagebase()
    labeledIatDict = dict()
    for i in labeledIatList:
        curRva, curIatLabel = i.split('\t')
        labeledIatDict[imageBase + int(curRva, 16)] = curIatLabel
    
    labeledCount = 0
    unresolvedList = []
    for entry in iatList:
        ea = idaapi.get_name_ea(0, entry)
        curIatLabel = labeledIatDict.get(ea, None)
        if curIatLabel != None:
            idc.set_name(ea, curIatLabel, 0)
            labeledCount += 1
        else:
            unresolvedList.append('could not resolve address 0x{:x}'.format(ea))

    print('labeled {:x} dynamically resolved IAT entries'.format(labeledCount))
    
    if len(unresolvedList) != 0:
        print('[*] ERROR, was not able to resolve {:x} entries'.format(len(unresolvedList)))
        print('\n'.join(unresolvedList)) 

class apply_iat_labels_plugin_t(idaapi.plugin_t):
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
        file_path = QtWidgets.QFileDialog.getOpenFileName(
            None, 'Open IAT file', os.curdir, "*.*")

        if len(file_path[0]) == 0:
            return

        iatList = Get_Dynamically_Resolved_Iat_Addresses()
        Label_Dynamically_Resolved_Iat_Addresses(iatList, file_path[0])

    def term(self):
        pass

def PLUGIN_ENTRY():
    return apply_iat_labels_plugin_t()