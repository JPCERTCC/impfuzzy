# Searching the ImpFuzzy and Imphash for Volatility3
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv impfuzzy.py volatility/plugins
# 3. python vol.py [ imphashlist | imphashsearch | impfuzzy ] -f
#    images.mem --profile=Win7SP1x64

import io
import logging

from volatility.framework import interfaces, constants, exceptions
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions
from volatility.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)

try:
    import pefile
except ImportError:
    vollog.info("Python pefile module not found, plugin (and dependent plugins) not available")
    raise

try:
    import pyimpfuzzy
    import impfuzzyutil
except ImportError:
    vollog.info("Python pyimpfuzzy module not found, plugin (and dependent plugins) not available")
    raise

vollog = logging.getLogger(__name__)


class ImpHashList(interfaces.plugins.PluginInterface):
    """Listing the Import Hash(imphash)"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.BooleanRequirement(name = "FASTMODE",
                                                description = "Use Fast scan mode (Not use impscan)",
                                                default = False,
                                                optional = True),
                requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
                requirements.PluginRequirement(name = 'vadinfo', plugin = vadinfo.VadInfo, version = (1, 0, 0)),
        ]

    @classmethod
    def calc_hash(cls, pe_data):
        """Get PE imphash and impfuzzy.
        Args:
            pe_data: PE image data
        """

        try:
            pe = pefile.PE(data=pe_data)
            hash_result = pe.get_imphash()
        except:
            hash_result = "Error: This file is not PE file imphash"

        try:
            fuzzy_result = pyimpfuzzy.get_impfuzzy_data(pe_data)
        except:
            fuzzy_result = "Error: This file is not PE file impfuzzy"

        return hash_result, fuzzy_result

    def _generator(self, procs):
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)

        filter_func = lambda _: False
        if self.config.get('address', None) is not None:
            filter_func = lambda x: x.get_start() not in [self.config['address']]

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            for vad in vadinfo.VadInfo.list_vads(proc, filter_func = filter_func):

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
                                                     offset = vad.get_start(),
                                                     layer_name = proc_layer_name)

                    pe_data = io.BytesIO()

                    for offset, data in dos_header.reconstruct():
                        pe_data.seek(offset)
                        pe_data.write(data)

                    pe_data_raw = pe_data.getvalue()

                    pe_data.close()

                    result_text, _ = self.calc_hash(pe_data_raw)
                except Exception:
                    result_text = "Unable to dump PE at {0:#x}".format(vad.get_start())

                yield (0, (proc.UniqueProcessId, process_name, format_hints.Hex(mod.DllBase), BaseDllName, result_text))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", format_hints.Hex), ("Name", str), ("Module Base", format_hints.Hex), ("Module Name", str), ("imphash", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))


class ImpHashSearch(ImpHashList):
    """Searching the Import Hash(imphash)"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.BooleanRequirement(name = "FASTMODE",
                                                description = "Use Fast scan mode (Not use impscan)",
                                                default = False,
                                                optional = True),
                requirements.StringRequirement(name = "IMPHASH",
                                               description = "Search single imphash value",
                                               optional = True),
                requirements.StringRequirement(name = "IMPHASHLIST",
                                               description = "Search imphash list file",
                                               optional = True),
        ]

    def _generator(self, procs):
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)

        hashlist = []
        if self.config.get('IMPHASH', None) is not None:
            hashlist.append(self.config['IMPHASH'])
        elif self.config.get('IMPHASHLIST', None) is not None:
            rf = resources.ResourceAccessor().open(self.config['IMPHASHLIST'], "r")
            lines = rf.readlines()
            for line in lines:
                hashlist.append(line.rstrip())
        else:
            vollog.error("No search hash, please set IMPHASH or IMPHASHLIST.")

        filter_func = lambda _: False
        if self.config.get('address', None) is not None:
            filter_func = lambda x: x.get_start() not in [self.config['address']]

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            for vad in vadinfo.VadInfo.list_vads(proc, filter_func = filter_func):

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
                                                     offset = vad.get_start(),
                                                     layer_name = proc_layer_name)

                    pe_data = io.BytesIO()

                    for offset, data in dos_header.reconstruct():
                        pe_data.seek(offset)
                        pe_data.write(data)

                    pe_data_raw = pe_data.getvalue()

                    pe_data.close()

                    result_text, _ = self.calc_hash(pe_data_raw)
                except Exception:
                    result_text = "Unable to dump PE at {0:#x}".format(vad.get_start())

                yield (0, (proc.UniqueProcessId, process_name, format_hints.Hex(mod.DllBase), BaseDllName, result_text))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", format_hints.Hex), ("Name", str), ("Module Base", format_hints.Hex), ("Module Name", str), ("imphash", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
