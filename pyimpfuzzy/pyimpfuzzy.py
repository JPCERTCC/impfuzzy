#!/usr/bin/env python

import pefile
import impfuzzyutil
import ordlookup


def get_impfuzzy(file):
    pe = pefileEx(file)
    apilist = pe.calc_impfuzzy()

    return impfuzzyutil.hash_data(apilist)


def get_impfuzzy_data(file):
    pe = pefileEx(data=file)
    apilist = pe.calc_impfuzzy()

    return impfuzzyutil.hash_data(apilist)


def hash_compare(hash1, hash2):
    return impfuzzyutil.compare(hash1, hash2)


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

def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description=
                                     'compare impfuzzy hashes of files')
    parser.add_argument('file1', metavar='FILE1', help='PE file')
    parser.add_argument('file2', metavar='FILE2', help='PE file')
    args = parser.parse_args()

    hash1 = get_impfuzzy(args.file1)
    hash2 = get_impfuzzy(args.file2)
    print("ImpFuzzy1: %s" % hash1)
    print("ImpFuzzy2: %s" % hash2)
    print("Compare: %i" % hash_compare(hash1, hash2))

if __name__ == '__main__':
    main()
