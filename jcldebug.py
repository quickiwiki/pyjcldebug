# MIT License
#
# Copyright (c) 2016 quickiwiki
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import struct
import ctypes
import numpy


class JclBinDebugScanner:
    JCL_DBG_HEADER = '<Lc7i?'
    JCL_DBG_DATA_SIGNATURE = 0x4742444A
    JCL_DBG_HEADER_VERSION = b'\x01'

    cache_data = False
    valid_format = False

    def check_format(self):
        index = 0

        self.signature, self.version, self.units, self.source_names, self.symbols, self.line_numbers, self.words, self.module_name, self.check_sum, self.check_sum_valid = struct.unpack_from(
            self.JCL_DBG_HEADER, self.stream, index)

#remove
#        return

        header_size = struct.calcsize(self.JCL_DBG_HEADER)
        data_size = len(self.stream)
        index += header_size

        valid_format = (self.stream != b'') & (data_size > header_size) & (data_size % 4 == 0) & (
            self.signature == self.JCL_DBG_DATA_SIGNATURE) & (self.version == self.JCL_DBG_HEADER_VERSION)
        if valid_format & self.check_sum_valid:
            data_index = 0
            file_check_sum = -self.check_sum
            end_data = data_size
            int_size = ctypes.sizeof(ctypes.c_int)

            while data_index < end_data:
                file_check_sum += int.from_bytes(self.stream[data_index: data_index + int_size], byteorder='little')
                file_check_sum = numpy.int32(file_check_sum)
                data_index += int_size

            file_check_sum = (0xFFFFFF & (file_check_sum >> 8)) | (file_check_sum << 24)
            self.valid_format = file_check_sum == self.check_sum

    def __init__(self, stream, cache_data):
        self.stream = stream
        self.cache_data = cache_data
        self.check_format()

    #
    # // JCL binary debug format string encoding/decoding routines
    # { Strings are compressed to following 6bit format (A..D represents characters) and terminated with }
    # { 6bit #0 char. First char = #1 indicates non compressed text, #2 indicates compressed text with   }
    # { leading '@' character                                                                            }
    # {                                                                                                  }
    # { 7   6   5   4   3   2   1   0  |                                                                 }
    # {---------------------------------                                                                 }
    # { B1  B0  A5  A4  A3  A2  A1  A0 | Data byte 0                                                     }
    # {---------------------------------                                                                 }
    # { C3  C2  C1  C0  B5  B4  B3  B2 | Data byte 1                                                     }
    # {---------------------------------                                                                 }
    # { D5  D4  D3  D2  D1  D0  C5  C4 | Data byte 2                                                     }
    # {---------------------------------                                                                 }
    @staticmethod
    def simple_crypt_string(s):
        result = bytearray(b'')

        for char in s:
            if char == 0x0:
                break
            elif char != 0xAA:
                char ^= 0xAA

            result.append(char)

        return result.decode(encoding='UTF-8')

    def decode_name_string(self, addr):
        buffer = bytearray(b'')
        b = 0
        index = addr
        p = self.stream[index]
        if p == 1:
            return self.simple_crypt_string(self.stream[index + 1 : len(self.stream)])
        elif p == 2:
            addr += 1
            buffer.append('@')
            b += 1

        i = 0
        c = 0

        while b < 255:
            val = i & 0x03
            if val == 0:
                c = self.stream[index] & 0x3f
            elif val == 1:
                c = (self.stream[index] >> 6) & 0x03
                index += 1
                c += (self.stream[index] & 0x0f) << 2
            elif val == 2:
                c = (self.stream[index] >> 4) & 0x0f
                index += 1
                c += (self.stream[index] & 0x03) << 4
            elif val == 3:
                c = (self.stream[index] >> 2) & 0x3f
                index += 1

            if c == 0x00:
                break
            elif c in range(0x01, 0xa):
                c += ord('0') - 0x01
            elif c in range(0x0b, 0x24):
                c += ord('A') - 0x0b
            elif c in range(0x25, 0x3e):
                c += ord('a') - 0x25
            elif c == 0x3f:
                c = ord('_')

            buffer.append(c)
            b += 1
            i += 1

        #buffer.append(0)
        return buffer.decode(encoding='UTF-8')

    def read_value(self, p, value):
        n = 0
        i = 0
        b = 0x80

        while (b & 0x80) != 0:
            b = self.stream[p]
            p += 1
            n += (b & 0x7f) << i
            n = numpy.int32(n)
            i += 7

        value = n
        return value != 0x7FFFFFFF, p, value

    def module_start_from_addr(self, addr):
        p = self.units
        start_addr = 0
        module_start_addr = ctypes.c_uint32(-1); #DWORD(-1)
        value = ctypes.c_uint32(0)

        res, p, value = self.read_value(p, value)
        while res:
            start_addr += value
            if addr < start_addr:
                break
            else:
                res, p, value = self.read_value(p, value)
                module_start_addr = start_addr

            res, p, value = self.read_value(p, value)

        return module_start_addr

    def line_number_from_addr(self, addr):
        module_start_va = self.module_start_from_addr(addr);
        line_number = 0
        offset = 0
        value = 0
        if self.cache_data:
            # todo: implement
            # cache_line_number()
            for value in reversed(self.line_numbers):
                if value.va <= addr:
                    if value.va >= module_start_va:
                        line_number = value.line_number
                        offset = addr - value.va

                    break
        else:
            p = self.line_numbers
            curr_va = 0
            item_va = 0
            res, p, value = self.read_value(p, value)
            while res:
                curr_va += value
                if addr < curr_va:
                    if item_va < module_start_va:
                        line_number = 0
                        offset = 0

                    break
                else:
                    item_va = curr_va
                    res, p, value = self.read_value(p, value)
                    line_number += value
                    offset = addr - curr_va

                res, p, value = self.read_value(p, value)

        return line_number, offset

    def data_to_str(self, a):
        if a == 0:
            return r''

        p = a + self.words - 1;
        return self.decode_name_string(p);

    def source_name_from_addr(self, addr):
        module_start_addr = self.module_start_from_addr(addr)
        p = self.source_names
        name = 0
        start_addr = 0
        item_addr = 0
        found = False
        value = 0

        res, p, value = self.read_value(p, value)
        while res:
            start_addr += value
            if addr < start_addr:
                if item_addr < module_start_addr:
                    name = 0
                else:
                    found = True
                break
            else:
                item_addr = start_addr
                res, p, value = self.read_value(p, value)
                name += value

            res, p, value = self.read_value(p, value)

        if found:
            return self.data_to_str(name)
        else:
            return ''

    def module_name_from_addr(self, addr):
        p = self.units
        name = 0
        start_addr = 0
        value = 0
        res, p, value = self.read_value(p, value)

        while res:
            start_addr += value
            if addr < start_addr:
                break
            else:
                res, p, value = self.read_value(p, value)
                name += value

            res, p, value = self.read_value(p, value)

        return self.data_to_str(name)

    def proc_name_from_addr(self, addr):
        module_start_addr = self.module_start_from_addr(addr)
        first_word = 0
        second_word = 0
        offset = 0
        if self.cache_data:
            # todo: implement
            # cache_proc_names()
            for value in reversed(self.proc_names):
                if value.addr <= addr:
                    if value.addr >= module_start_addr:
                        first_word = value.first_word
                        second_word = value.second_word
                        offset = addr - value.addr

                    break
        else:
            p = self.symbols
            curr_addr = 0
            item_addr = 0
            value = 0

            res, p, value = self.read_value(p, value)
            while res:
                curr_addr += value
                if addr < curr_addr:
                    if item_addr < module_start_addr:
                        first_word = 0
                        second_word = 0
                        offset = 0

                    break
                else:
                    item_addr = curr_addr
                    res, p, value = self.read_value(p, value)
                    first_word += value
                    res, p, value = self.read_value(p, value)
                    second_word += value
                    offset = addr - curr_addr

                res, p, value = self.read_value(p, value)

            result = ''
            if first_word != 0:
                result = self.data_to_str(first_word)
                if second_word != 0:
                    result += '.' + self.data_to_str(second_word)

            return result, offset
