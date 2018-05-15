#!/usr/bin/env python

import sys
import ctypes
import pefile
import ordlookup
from os.path import join
from os.path import split
from pip._vendor import six

# Length of an individual fuzzy hash signature component
SPAMSUM_LENGTH = 64

# The longest possible length for a fuzzy hash signature
FUZZY_MAX_RESULT = (2 * SPAMSUM_LENGTH + 20)

is_64bits = sys.maxsize > 2**32
_package_path = split(__file__)[0]
_lib_path = join(_package_path, r'bin\fuzzy64.dll' if is_64bits else r'bin\fuzzy.dll')
fuzzy_lib = ctypes.cdll.LoadLibrary(_lib_path)

def _get_hash(pe):
    apilist = pe.calc_impfuzzy()
    if isinstance(apilist, six.text_type):
        apilist = apilist.encode("ascii")

    result_buffer = ctypes.create_string_buffer(FUZZY_MAX_RESULT)
    file_buffer = ctypes.create_string_buffer(apilist)
    hash_result = fuzzy_lib.fuzzy_hash_buf(file_buffer, len(file_buffer) - 1, result_buffer)
    hash_value = result_buffer.value.decode("ascii")

    return hash_value

def get_impfuzzy(file):
    pe = pefileEx(file)

    return _get_hash(pe)


def get_impfuzzy_data(file):
    pe = pefileEx(data=file)

    return _get_hash(pe)


def hash_compare(hash1, hash2):
    if isinstance(hash1, six.text_type):
        hash1 = hash1.encode("ascii")

    if isinstance(hash2, six.text_type):
        hash2 = hash2.encode("ascii")

    hash_1_buffer = ctypes.create_string_buffer(hash1)
    hash_2_buffer = ctypes.create_string_buffer(hash2)

    return fuzzy_lib.fuzzy_compare(hash_1_buffer, hash_2_buffer)


class pefileEx(pefile.PE):

    def __init__(self, *args, **kwargs):
        pefile.PE.__init__(self, *args, **kwargs)

    def calc_impfuzzy(self):
        impstrs = []
        exts = ["ocx", "sys", "dll"]
        if not hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            return ""
        for entry in self.DIRECTORY_ENTRY_IMPORT:
            no_iat_flag = False
            if isinstance(entry.dll, bytes):
                libname = entry.dll.decode().lower()
            else:
                libname = entry.dll.lower()
            parts = libname.rsplit(".", 1)
            if len(parts) > 1 and parts[1] in exts:
                libname = parts[0]

            if not entry.imports[0].struct_iat:
                no_iat_flag = True

            for imp in entry.imports:
                funcname = None
                if imp.struct_iat or no_iat_flag:
                    if not imp.name:
                        funcname = ordlookup.ordLookup(
                            entry.dll.lower(), imp.ordinal, make_name=True)
                        if not funcname:
                            raise Exception("Unable to look up ordinal %s:%04x" % (
                                entry.dll, imp.ordinal))
                    else:
                        funcname = imp.name

                if not funcname:
                    continue

                if isinstance(funcname, bytes):
                    funcname = funcname.decode()
                impstrs.append("%s.%s" % (libname.lower(), funcname.lower()))

        apilist = ",".join(impstrs)
        return apilist
