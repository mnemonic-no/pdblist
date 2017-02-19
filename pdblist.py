# ISC License
#
# Copyright (c) 2017, mnemonic AS <opensource@mnemonic.no>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""This module lists the PDB information from running services and processes.

@author:        Geir Skjotskift
@license:       ISC License
@contact:       opensource@mnemonic.no
"""

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32

IMAGE_DEBUG_TYPE_UNKNOWN          = 0
IMAGE_DEBUG_TYPE_COFF             = 1
IMAGE_DEBUG_TYPE_CODEVIEW         = 2
IMAGE_DEBUG_TYPE_FPO              = 3
IMAGE_DEBUG_TYPE_MISC             = 4
IMAGE_DEBUG_TYPE_EXCEPTION        = 5
IMAGE_DEBUG_TYPE_FIXUP            = 6
IMAGE_DEBUG_TYPE_OMAP_TO_SRC      = 7
IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    = 8
IMAGE_DEBUG_TYPE_BORLAND          = 9
IMAGE_DEBUG_TYPE_RESERVED10       = 10
IMAGE_DEBUG_TYPE_CLSID            = 11

datatypes = {
        '_PDBGUID'      : [ 0x10, {
            'Data1'         : [ 0x00, [ 'array', 4, ['unsigned char']]],
            'Data2'         : [ 0x04, [ 'array', 2, ['unsigned char']]],
            'Data3'         : [ 0x06, [ 'array', 2, ['unsigned char']]],
            'Data4'         : [ 0x08, [ 'array', 2, ['unsigned char']]],
            'Data5'         : [ 0x10, [ 'array', 6, ['unsigned char']]],
            }],
        '_CV_HEADER' : [ 0x8, {
            'Signature'     : [ 0x00, [ 'String', {'length': 4}]],
            'Offset'        : [ 0x04, [ 'unsigned long' ]],
            }],
        '_CV_HEADER_SIMPLE': [ 0x04, {
            'Signature'     : [ 0x00, [ 'String', {'length': 4}]]
            }],
        '_CV_INFO_PDB20' : [ None, {
            'CvHeader'      : [ 0x00, [ '_CV_HEADER' ]],
            'Signature'     : [ 0x08, [ 'unsigned long' ]],
            'Age'           : [ 0x0c, [ 'unsigned long' ]],
            'PdbFileName'   : [ 0x10, [ 'String', {'length': 0x7c, 'encoding': 'utf8'} ]]
            }],
        '_CV_INFO_PDB70' : [ None, {
            'CvHeader'      : [ 0x00, [ '_CV_HEADER_SIMPLE' ]],
            'Signature'     : [ 0x04, [ '_PDBGUID' ]],
            'Age'           : [ 0x14, [ 'unsigned long' ]],
            'PdbFileName'   : [ 0x18, [ 'String', {'length': 0x7c, 'encoding': 'utf8'} ]]
            }],
        '_IMAGE_DEBUG_MISC' : [ None, {
            'DataType'      : [ 0x00, [ 'unsigned long' ]],
            'Length'        : [ 0x04, [ 'unsigned long' ]],
            'Unicode'       : [ 0x08, [ 'unsigned short' ]],
            'Reserved'      : [ 0x0a, [ 'array', 3, ['unsigned char']]],
            'Data'          : [ 0x0d, [ 'String', {
                'encoding': lambda x: "uft16" if x.Unicode else "utf8",
                'length': lambda x: x.Length}]],
            }],
        }


class _PDBGUID(obj.CType):
    def __str__(self):
        def chrarray2str(a):
            c1 = ["{0:02x}".format(x.v()) for x in a]
            return "".join(c1)
        return "{0}-{1}-{2}-{3}-{4}".format(
                chrarray2str(self.Data1),
                chrarray2str(self.Data2),
                chrarray2str(self.Data3),
                chrarray2str(self.Data4),
                chrarray2str(self.Data5))


class PDBDataTypes(obj.ProfileModification):

    def modification(self, profile):

        profile.vtypes.update(datatypes)
        profile.object_classes.update({
            '_PDBGUID': _PDBGUID
            })


class PDBList(common.AbstractWindowsCommand):
    """Extract and show the PDB information in running services and processes."""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def logverbose(self, msg):
        if self._config.VERBOSE:
            debug.info(msg)

    def _procs_and_modules(self, ps_list):

        for proc in ps_list:
            for mod in proc.get_load_modules():
                yield proc, mod

    def _is_valid_debug_dir(self, debug_dir, image_base, addr_space):
        if debug_dir == None:
            self.logverbose("debug_dir is None")
            return False

        if debug_dir.AddressOfRawData == 0:
            self.logverbose("debug_dir == 0")
            return False

	start_addr = image_base + debug_dir.AddressOfRawData
        if not addr_space.is_valid_address(start_addr):
            self.logverbose("Invalid address (data start): {0:#x}".format(start_addr))
            return False

	end_addr = image_base + debug_dir.AddressOfRawData + debug_dir.SizeOfData - 1
        if not addr_space.is_valid_address(end_addr):
            self.logverbose("Invalid addres (data end): {0:#x}".format(end_addr))
            return False

	return True

    def _get_debug_symbols(self, addr_space, mod):

        image_base = mod.DllBase
        debug_dir = mod.get_debug_directory()

        if not self._is_valid_debug_dir(debug_dir, image_base, addr_space):
            self.logverbose("Invalid debugdir {0:#x} {1:#x}".format(
                debug_dir.v(),
                image_base.v()))
            return None

        debug_data =  debug_data = addr_space.zread(
                image_base + debug_dir.AddressOfRawData,
                debug_dir.SizeOfData)

        if debug_data[:4] == 'RSDS':
            return obj.Object("_CV_INFO_PDB70",
                    offset = image_base + debug_dir.AddressOfRawData,
                    vm = addr_space)

        if debug_data[:4] == 'NB10':
            return obj.Object("_CV_INFO_PDB20",
                    offset = image_base + debug_dir.AddressOfRawData,
                    vm = addr_space)
        return None

    def calculate(self):

        address_space = utils.load_as(self._config)

        ps_list = win32.tasks.pslist(address_space)

        #TODO PROCESS

        # USER modules
        for proc, mod in self._procs_and_modules(ps_list):
            proc_as = proc.get_process_address_space()
            dbg = self._get_debug_symbols(proc_as, mod)

            if dbg is None:
                continue

            yield (mod.DllBase.v(),
                   proc.UniqueProcessId,
                   proc.ImageFileName,
                   mod.FullDllName,
                   dbg.CvHeader.Signature,
                   dbg.PdbFileName)


        # KERNEL modules

        for mod in win32.modules.lsmod(address_space):
            dbg = self._get_debug_symbols(address_space, mod)
            if dbg is None:
                continue
            yield (mod.DllBase.v(),
                   "-",
                   "KERNEL",
                   mod.FullDllName,
                   dbg.CvHeader.Signature,
                   dbg.PdbFileName)


    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "#018x"),
            ("PID", ">10"),
            ("Service", "<16"),
            ("Module", "<48"),
            ("Sig", "4"),
            ("Value", "")])

        for offset, pid, service, module, signature, value in data:
            self.table_row(outfd,
                    offset, pid, service, module, signature, value)

