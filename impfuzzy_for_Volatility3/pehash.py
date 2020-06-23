# Search PE File with ImpFuzzy / Imphash / Ssdeep for Volatility3
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#
# How to use:
# 1. git clone https://github.com/JPCERTCC/impfuzzy.git
# 2. python3 vol.py -f memdata --plugin-dirs impfuzzy/impfuzzy_for_Volatility3 [ pehash.ImpHash | pehash.ImpFuzzy | pehash.Ssdeep ]
#

import logging, os, io

from volatility.framework import interfaces, constants, exceptions, renderers
from volatility.framework.objects import utility
from volatility.framework.layers import resources
from volatility.framework.renderers import format_hints
from volatility.framework.configuration import requirements
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions
from volatility.framework.symbols.windows.extensions import pe
from volatility.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)

try:
    import pefile
    has_pefile = True
except ImportError:
    has_pefile = False

try:
    import pyimpfuzzy
    import impfuzzyutil
    has_pyimpfuzzy = True
except ImportError:
    has_pyimpfuzzy = False

try:
    import ssdeep
    has_ssdeep = True
except ImportError:
    has_ssdeep = False

vollog = logging.getLogger(__name__)


class ImpHash(interfaces.plugins.PluginInterface):
    """Listing the Import Hash (imphash)"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Memory layer for the kernel',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
                requirements.IntRequirement(name='pid',
                                            description="Process ID to include (all other processes are excluded)",
                                            optional=True),
                requirements.StringRequirement(name="imphash",
                                               description="Search single imphash value",
                                               optional=True),
                requirements.StringRequirement(name="imphashlist",
                                               description="Search imphash list file",
                                               optional=True),
                requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(1, 0, 0)),
                requirements.PluginRequirement(name='vadinfo', plugin=vadinfo.VadInfo, version=(1, 0, 0)),
                ]

    @classmethod
    def calc_hash(cls, pe_data):
        try:
            pe = pefile.PE(data=pe_data)
            hash_result = pe.get_imphash()
        except:
            hash_result = "Unable to calc imphash"

        return hash_result

    def _generator(self, procs, hashlist):
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types=pe.class_types)

        filter_func = lambda _: False
        if self.config.get('address', None) is not None:
            filter_func = lambda x: x.get_start() not in [self.config['address']]

        for proc in procs:

            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            for vad in vadinfo.VadInfo.list_vads(proc, filter_func=filter_func):

                # this parameter is inherited from the VadInfo plugin. if a user specifies
                # an address, then it bypasses the DLL identification heuristics
                if self.config.get("address", None) is None:

                    # rather than relying on the PEB for DLLs, which can be swapped,
                    # it requires special handling on wow64 processes, and its
                    # unreliable from an integrity standpoint, let's use the VADs instead
                    protection_string = vad.get_protection(
                        vadinfo.VadInfo.protect_values(self.context, self.config['primary'], self.config['nt_symbols']),
                        vadinfo.winnt_protections)

                    # DLLs are write copy...
                    if protection_string != "PAGE_EXECUTE_WRITECOPY":
                        continue

                    # DLLs have mapped files...
                    if isinstance(vad.get_file_name(), interfaces.renderers.BaseAbsentValue):
                        continue

                try:
                    dos_header = self.context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                                     offset=vad.get_start(),
                                                     layer_name=proc_layer_name)

                    pe_data = io.BytesIO()

                    for offset, data in dos_header.reconstruct():
                        pe_data.seek(offset)
                        pe_data.write(data)

                    pe_data_raw = pe_data.getvalue()

                    pe_data.close()

                    result_text = self.calc_hash(pe_data_raw)
                except Exception:
                    result_text = "Unable to dump PE at {0:#x}".format(vad.get_start())

                if (result_text in hashlist and len(result_text) == 32) or len(hashlist) == 0:
                    yield (0, (proc.UniqueProcessId, proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace'), format_hints.Hex(vad.get_start()), vad.get_file_name(), result_text))

    def run(self):
        if not has_pefile:
            vollog.info("Python pefile module not found, plugin (and dependent plugins) not available")
            raise

        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        hashlist = []
        if self.config.get('imphash', None) is not None:
            hashlist.append(self.config['imphash'])
        elif self.config.get('imphashlist', None) is not None:
            rf = open(self.config['imphashlist'], "r")
            lines = rf.readlines()
            for line in lines:
                hashlist.append(line.rstrip())

        return renderers.TreeGrid([("PID", int), ("ImageFileName", str), ("Module Base", format_hints.Hex), ("Module Name", str), ("imphash", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context=self.context,
                                                                   layer_name=self.config['primary'],
                                                                   symbol_table=self.config['nt_symbols'],
                                                                   filter_func=filter_func), hashlist))


class ImpFuzzy(interfaces.plugins.PluginInterface):
    """Listing the Import Fuzzy Hashing (impfuzzy)"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Memory layer for the kernel',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
                requirements.IntRequirement(name='pid',
                                            description="Process ID to include (all other processes are excluded)",
                                            optional=True),
                requirements.StringRequirement(name="impfuzzy",
                                               description="Search single impfuzzy value",
                                               optional=True),
                requirements.StringRequirement(name="impfuzzylist",
                                               description="Search impfuzzy list file",
                                               optional=True),
                requirements.StringRequirement(name="exefile",
                                               description="Comparing the PE file or direcroty",
                                               optional=True),
                requirements.IntRequirement(name='threshold',
                                            description="Import fuzzy hashing threshold (Default 30)",
                                            optional=True),
                requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(1, 0, 0)),
                requirements.PluginRequirement(name='vadinfo', plugin=vadinfo.VadInfo, version=(1, 0, 0)),
                ]

    @classmethod
    def calc_hash(cls, pe_data):
        try:
            fuzzy_result = pyimpfuzzy.get_impfuzzy_data(pe_data)
        except:
            fuzzy_result = "Unable to calc impfuzzy"

        return fuzzy_result

    def _generator(self, procs, hashlist, threshold):
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types=pe.class_types)

        filter_func = lambda _: False
        if self.config.get('address', None) is not None:
            filter_func = lambda x: x.get_start() not in [self.config['address']]

        for proc in procs:

            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            for vad in vadinfo.VadInfo.list_vads(proc, filter_func=filter_func):

                # this parameter is inherited from the VadInfo plugin. if a user specifies
                # an address, then it bypasses the DLL identification heuristics
                if self.config.get("address", None) is None:

                    # rather than relying on the PEB for DLLs, which can be swapped,
                    # it requires special handling on wow64 processes, and its
                    # unreliable from an integrity standpoint, let's use the VADs instead
                    protection_string = vad.get_protection(
                        vadinfo.VadInfo.protect_values(self.context, self.config['primary'], self.config['nt_symbols']),
                        vadinfo.winnt_protections)

                    # DLLs are write copy...
                    if protection_string != "PAGE_EXECUTE_WRITECOPY":
                        continue

                    # DLLs have mapped files...
                    if isinstance(vad.get_file_name(), interfaces.renderers.BaseAbsentValue):
                        continue

                try:
                    dos_header = self.context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                                     offset=vad.get_start(),
                                                     layer_name=proc_layer_name)

                    pe_data = io.BytesIO()

                    for offset, data in dos_header.reconstruct():
                        pe_data.seek(offset)
                        pe_data.write(data)

                    pe_data_raw = pe_data.getvalue()

                    pe_data.close()

                    result_text = self.calc_hash(pe_data_raw)
                except Exception:
                    result_text = "Unable to dump PE at {0:#x}".format(vad.get_start())

                if len(hashlist) == 0:
                    yield (0, (proc.UniqueProcessId, proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace'), format_hints.Hex(vad.get_start()), vad.get_file_name(), result_text))
                elif not "Unable" in result_text:
                    for hash in hashlist:
                        if pyimpfuzzy.hash_compare(result_text, hash) >= threshold:
                            yield (0, (proc.UniqueProcessId, proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace'), format_hints.Hex(vad.get_start()), vad.get_file_name(), result_text))

    def run(self):
        if not has_pyimpfuzzy:
            vollog.info("Python pyimpfuzzy module not found, plugin (and dependent plugins) not available")
            raise

        # This is a impfuzzys threshold
        if self.config.get('threshold', None) is not None:
            threshold = self.config['threshold']
        else:
            threshold = 30

        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        files = []
        hashlist = []
        if self.config.get('impfuzzy', None) is not None:
            hashlist.append(self.config['impfuzzy'])
        elif self.config.get('impfuzzylist', None) is not None:
            rf = open(self.config['impfuzzylist'], "r")
            lines = rf.readlines()
            for line in lines:
                hashlist.append(line.rstrip())
        elif self.config.get('exefile', None) is not None:
            if os.path.isdir(self.config['exefile']):
                for root, dirs, filenames in os.walk(self.config['exefile']):
                    for name in filenames:
                        files.append(os.path.join(root, name))
            elif os.path.isfile(self.config['exefile']):
                files.append(self.config['exefile'])

            for file in files:
                hashlist.append(pyimpfuzzy.get_impfuzzy(file))

        return renderers.TreeGrid([("PID", int), ("ImageFileName", str), ("Module Base", format_hints.Hex), ("Module Name", str), ("impfuzzy", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context=self.context,
                                                                   layer_name=self.config['primary'],
                                                                   symbol_table=self.config['nt_symbols'],
                                                                   filter_func=filter_func), hashlist, threshold))


class Ssdeep(interfaces.plugins.PluginInterface):
    """Listing the File ssdeep"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Memory layer for the kernel',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
                requirements.IntRequirement(name='pid',
                                            description="Process ID to include (all other processes are excluded)",
                                            optional=True),
                requirements.StringRequirement(name="ssdeep",
                                               description="Search single ssdeep value",
                                               optional=True),
                requirements.StringRequirement(name="ssdeeplist",
                                               description="Search ssdeep list file",
                                               optional=True),
                requirements.StringRequirement(name="exefile",
                                               description="Comparing the PE file or direcroty",
                                               optional=True),
                requirements.IntRequirement(name='threshold',
                                            description="Ssdeep threshold (Default 30)",
                                            optional=True),
                requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(1, 0, 0)),
                requirements.PluginRequirement(name='vadinfo', plugin=vadinfo.VadInfo, version=(1, 0, 0)),
                ]

    @classmethod
    def calc_hash(cls, pe_data):
        try:
            fuzzy_result = ssdeep.hash(pe_data)
        except:
            fuzzy_result = "Unable to calc ssdeep"

        return fuzzy_result

    def _generator(self, procs, hashlist, threshold):
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types=pe.class_types)

        filter_func = lambda _: False
        if self.config.get('address', None) is not None:
            filter_func = lambda x: x.get_start() not in [self.config['address']]

        for proc in procs:

            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            for vad in vadinfo.VadInfo.list_vads(proc, filter_func=filter_func):

                # this parameter is inherited from the VadInfo plugin. if a user specifies
                # an address, then it bypasses the DLL identification heuristics
                if self.config.get("address", None) is None:

                    # rather than relying on the PEB for DLLs, which can be swapped,
                    # it requires special handling on wow64 processes, and its
                    # unreliable from an integrity standpoint, let's use the VADs instead
                    protection_string = vad.get_protection(
                        vadinfo.VadInfo.protect_values(self.context, self.config['primary'], self.config['nt_symbols']),
                        vadinfo.winnt_protections)

                    # DLLs are write copy...
                    if protection_string != "PAGE_EXECUTE_WRITECOPY":
                        continue

                    # DLLs have mapped files...
                    if isinstance(vad.get_file_name(), interfaces.renderers.BaseAbsentValue):
                        continue

                try:
                    dos_header = self.context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                                     offset=vad.get_start(),
                                                     layer_name=proc_layer_name)

                    pe_data = io.BytesIO()

                    for offset, data in dos_header.reconstruct():
                        pe_data.seek(offset)
                        pe_data.write(data)

                    pe_data_raw = pe_data.getvalue()

                    pe_data.close()

                    result_text = self.calc_hash(pe_data_raw)
                except Exception:
                    result_text = "Unable to dump PE at {0:#x}".format(vad.get_start())

                if len(hashlist) == 0:
                    yield (0, (proc.UniqueProcessId, proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace'), format_hints.Hex(vad.get_start()), vad.get_file_name(), result_text))
                elif not "Unable" in result_text:
                    for hash in hashlist:
                        if ssdeep.compare(result_text, hash) >= threshold:
                            yield (0, (proc.UniqueProcessId, proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace'), format_hints.Hex(vad.get_start()), vad.get_file_name(), result_text))

    def run(self):
        if not has_ssdeep:
            vollog.info("Python ssdeep module not found, plugin (and dependent plugins) not available")
            raise

        # This is a ssdeep threshold
        if self.config.get('threshold', None) is not None:
            threshold = self.config['threshold']
        else:
            threshold = 30

        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        hashlist = []
        if self.config.get('ssdeep', None) is not None:
            hashlist.append(self.config['ssdeep'])
        elif self.config.get('ssdeeplist', None) is not None:
            rf = open(self.config['ssdeeplist'], "r")
            lines = rf.readlines()
            for line in lines:
                hashlist.append(line.rstrip())
        elif self.config.get('exefile', None) is not None:
            if os.path.isdir(self.config['exefile']):
                for root, dirs, filenames in os.walk(self.config['exefile']):
                    for name in filenames:
                        files.append(os.path.join(root, name))
            elif os.path.isfile(self.config['exefile']):
                files.append(self.config['exefile'])

            for file in files:
                hashlist.append(ssdeep.hash(file))

        return renderers.TreeGrid([("PID", int), ("ImageFileName", str), ("Module Base", format_hints.Hex), ("Module Name", str), ("ssdeep", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context=self.context,
                                                                   layer_name=self.config['primary'],
                                                                   symbol_table=self.config['nt_symbols'],
                                                                   filter_func=filter_func), hashlist, threshold))
