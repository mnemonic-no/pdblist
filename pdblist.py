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
        '_GUID'      : [ 0x10, {
            'Data1'         : [ 0x00, [ 'array', 4, ['unsigned char']]],
            'Data2'         : [ 0x04, [ 'array', 2, ['unsigned char']]],
            'Data3'         : [ 0x06, [ 'array', 2, ['unsigned char']]],
            'Data4'         : [ 0x08, [ 'array', 2, ['unsigned char']]],
            'Data5'         : [ 0x10, [ 'array', 6, ['unsigned char']]],
            }],
        '_CV_HEADER' : [ 0x8, {
            'Signature'     : [ 0x00, [ 'unsigned long' ]],
            'Offset'        : [ 0x04, [ 'unsigned long' ]],
            }],
        '_CV_INFO_PDB20' : [ None, {
            'CvHeader'      : [ 0x00, [ '_CV_HEADER' ]],
            'Signature'     : [ 0x08, [ 'unsigned long' ]],
            'Age'           : [ 0x0c, [ 'unsigned long' ]],
            'PdbFileName'   : [ 0x10, [ 'String', {'encoding': 'utf8'} ]]
            }],
        '_CV_INFO_PDB70' : [ None, {
            'CvSignature'   : [ 0x00, [ 'unsigned long' ]],
            'Signature'     : [ 0x04, [ '_GUID' ]],
            'Age'           : [ 0x14, [ 'unsigned long' ]],
            'PdbFileName'   : [ 0x18, [ 'String', {'encoding': 'utf8'} ]]
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

class _GUID(obj.CType):
    def __str__(self):
        def chrarray2str(a):
            c1 = ["{0:02x}".format(ord(x)) for x in a1]
            return "".join(c1)
        return "{0}-{1}-{2}-{3}-{4}".format(
                chrarray2str(self.Data1),
                chrarray2str(self.Data2),
                chrarray2str(self.Data3),
                chrarray2str(self.Data4),
                chrarray2str(self.Data5))

class PDBList(common.AbstractWindowsCommand):
    """Extract and show the PDB information in running services and processes."""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def logverbose(self, msg):
        if self._config.VERBOSE:
            debug.info(msg)

    def calculate(self):
        pass

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "#018x"),
            ("PID", ">10"),
            ("Service", "<64"),
            ("Module", "<64"),
            ("USR", "<3"),
            ("Type", "<5"),
            ("Value", "")])


