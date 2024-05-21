from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers, symbols, objects, constants
from volatility3.framework.symbols import intermed
from volatility3.framework.objects import utility
from volatility3.framework.exceptions import PagedInvalidAddressException
from typing import Callable, Iterable, List, Any
from volatility3.plugins.linux import pslist
import logging
import binascii
import json


"""
OpenSSH Session Key Dumper plugin for Volatility 3
Dumps SSHENC structures from memory containing cipher name, key and IV used to encrypt SSH traffic.
By Jelle Vergeer
"""


vollog = logging.getLogger(__name__)

OPENSSH_ENC_ALGS = {
    #Name, block size, key size
    ("chacha20-poly1305@openssh.com", 8, 64,),
    ("des", 8, 8),
    ("3des", 8, 16),
    ("blowfish", 8, 32),
    ("blowfish-cbc", 8, 16),
    ("cast128-cbc", 8, 16),
    ("arcfour", 8, 16),
    ("arcfour128", 8, 16),
    ("arcfour256", 8, 32),
    ("acss@openssh.org", 16, 5),
    ("3des-cbc", 8, 24),
    ("aes128-cbc", 16, 16,),
    ("aes192-cbc", 16, 24,),
    ("aes256-cbc", 16, 32,),
    ("rijndael-cbc@lysator.liu.se", 16, 32,),
    ("aes128-ctr", 16, 16,),
    ("aes192-ctr", 16, 24,),
    ("aes256-ctr", 16, 32,),
    ("aes128-gcm@openssh.com", 16, 16,),
    ("aes256-gcm@openssh.com", 16, 32,),
}
OPENSSH_ENC_ALGS_LOOKUP = {}

for alg in OPENSSH_ENC_ALGS:
    OPENSSH_ENC_ALGS_LOOKUP[alg[0]] = alg


def lookup_enc(name):
    return OPENSSH_ENC_ALGS_LOOKUP.get(name, None)


class ScrapedKey(object):
    def __init__(self, task, sshenc, addr):
        self.task = task
        self.task_name = utility.array_to_string(task.comm)
        self.sshenc_addr = addr
        self.enc_name = None
        self.key = None
        self.iv = None
        self.sshenc = sshenc

    def as_dict(self):
        return {
            'task_name': self.task_name,
            'sshenc_addr': self.sshenc_addr,
            'cipher_name': self.enc_name,
            'key': self.key,
            'iv': self.iv
        }

    def __str__(self):        
        return "<Key enc_name={!r} sshenc_addr=0x{:x} key={} iv={} sshenc={} pid={}>".format(self.enc_name, self.sshenc_addr, self.key, self.iv, dump_ctype(self.sshenc), self.pid)

    def __eq__(self, other):
        return self.task.pid == other.task.pid and self.sshenc_addr == other.sshenc_addr

    def __ne__(self, other):
        return not self.__eq__(self, other)


class SSHKeyExtractor(object):
    def __init__(self, context, openssh_table_name, proc_layer_name, task, progress_callback):
        self.context = context
        self.openssh_table_name = openssh_table_name
        self.proc_layer_name = proc_layer_name
        self.proc_layer = self.context.layers[proc_layer_name]
        self.task = task
        self.task_name = utility.array_to_string(task.comm)
        self.openssh_symbols = self.context.symbol_space[openssh_table_name]
        self.progress_callback = progress_callback

    def construct_scraped_key(self, sshenc, ptr):
        key = ScrapedKey(self.task, sshenc, ptr)
       
        key.enc_name = utility.array_to_string(sshenc.name.dereference())
        key_raw = self.proc_layer.read(sshenc.key, sshenc.key_len)
        key.key = key_raw.hex()
        if sshenc.has_member("iv_len"):
            iv_len = sshenc.iv_len
        else:
            iv_len = sshenc.block_size
        iv_raw = self.proc_layer.read(sshenc.iv, iv_len)
        key.iv = iv_raw.hex()
        return key

    def probe_address(self, ptr):
        sshenc = self.context.object(self.openssh_table_name + constants.BANG + "sshenc_61p2", offset = ptr, layer_name = self.proc_layer_name)
        name_valid = sshenc.name.is_readable()
        cipher_valid = sshenc.cipher.is_readable()

        if not (name_valid and cipher_valid):
            return None

        enc_name = sshenc.name.dereference()
        enc_name = utility.array_to_string(enc_name)
        enc_properties = lookup_enc(enc_name)
        if not enc_properties:
            return None

        expected_key_len = enc_properties[2]
        key_len_valid = expected_key_len == sshenc.key_len
        if not key_len_valid:
            return None

        cipher_name = sshenc.cipher.name.dereference()
        cipher_name = utility.array_to_string(cipher_name)
        if cipher_name != enc_name:
            return None

        vollog.debug("Found possible candidate at address 0x{:x}.".format(ptr))

        #At this point we know pretty certain this is the sshenc struct. Let's figure out which version...
        expected_block_size = enc_properties[1]
        block_size_valid = expected_block_size == sshenc.block_size
        
        if not block_size_valid:
            vollog.warning("Detected structure misaslignment. Trying sshenc_61p1 structure..")
            sshenc = self.context.object(self.openssh_table_name + constants.BANG + "sshenc_61p1", offset = ptr, layer_name = self.proc_layer_name)

        block_size_valid = expected_block_size == sshenc.block_size
        if not block_size_valid:
            vollog.error("Detected sshenc structure but can't seem to align!")
            # Bugger we can't seem to properly align the structure
            return None

        key_valid = sshenc.key.is_readable()
        iv_valid = sshenc.iv.is_readable()
        if key_valid and iv_valid:
            return sshenc

        vollog.error("Detected sshenc structure but invalid key/IV address!")
        return None

    def extract(self):
        sshenc_size = max(self.openssh_symbols.get_type("sshenc_61p1").size, self.openssh_symbols.get_type("sshenc_61p2").size)
        regions = self.task.get_process_memory_sections(heap_only=True)
        regions = list(regions)
        total_size = 0
        bytes_scanned = 0
        keys_found = 0

        for region in regions:
            total_size += region[1]

        for region in regions:
            region_start = region[0]
            region_end = region[0] + region[1]
            ptr = region_start
            while ptr + sshenc_size < region_end:
                if ptr % 0x1000 == 0:
                    self.progress_callback((bytes_scanned / total_size) * 100, "Found {} keys scanning memory of #{} ({}), region 0x{:x} - 0x{:x}".format(keys_found, self.task.pid, self.task_name, region_start, region_end))
                try:
                    sshenc = self.probe_address(ptr)
                    if sshenc is not None:
                        key = self.construct_scraped_key(sshenc, ptr)
                        keys_found += 1
                        yield key
                except PagedInvalidAddressException:
                    pass
                ptr += 4
                bytes_scanned += 4


class SSHKeys(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 2, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True),
            requirements.ListRequirement(name = 'name',
                                         element_type = str,
                                         description = "Process name to include (all other processes are excluded)",
                                         optional = True),
            requirements.StringRequirement(name = 'out',
                                         description = "JSON output file",
                                         optional = True)
        ]

    def create_proc_filter(self) -> Callable[[Any], bool]:
        """Constructs a filter function for process IDs.

        Args:
            pid_list: List of process IDs that are acceptable (or None if all are acceptable)

        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        pid_list = self.config.get('pid', None) or []
        name_list = self.config.get('name', None) or []
        pid_list = [x for x in pid_list if x is not None]
        name_list = [x for x in name_list if x is not None]

        def filter_func(x):
            name = utility.array_to_string(x.comm)
            return (x.pid not in pid_list) and (name not in name_list)

        return filter_func

    def _generator(self, tasks):
        result = []
        kernel = self.context.modules[self.config['kernel']]
        is_32bit = not symbols.symbol_table_is_64bit(self._context, kernel.symbol_table_name)
        if is_32bit:
            openssh_json_file = "openssh32"
        else:
            openssh_json_file = "openssh64"

        openssh_table_name = intermed.IntermediateSymbolTable.create(self.context, self.config_path, '', openssh_json_file)

        for task in tasks:
            if not task.mm:
                continue

            name = utility.array_to_string(task.comm)
            vollog.info("Scanning process #{} ({} {})".format(task.pid, name, ""))
            proc_layer_name = task.add_process_layer()
            extractor = SSHKeyExtractor(self.context, openssh_table_name, proc_layer_name, task, self._progress_callback)
            keys = extractor.extract()
            result.extend(keys)
        return result

    def write_output_file(self, filepath, keys):
        fp = open(filepath, "w")
        d = []
        for key in keys:
            key_dict = key.as_dict()
            json.dump(key_dict, fp)
            fp.write("\n")
        fp.close()

    def run(self):
        data = []
        filter_func = self.create_proc_filter()
        tasks = pslist.PsList.list_tasks(self.context, self.config['kernel'], filter_func=filter_func)
        output_file =  self.config.get('out', None)
        
        keys = self._generator(tasks)
        if output_file:
            self.write_output_file(output_file, keys)

        result = []
        for key in keys:
            result.append((0, (key.task_name, key.task.pid, key.task.parent.pid, "", renderers.format_hints.Hex(key.sshenc_addr), key.enc_name, key.key, key.iv)))

        return renderers.TreeGrid([("Name", str),
                        ("Pid", int),
                        ("PPid", int),
                        ("Arguments", str),
                        ("Address", renderers.format_hints.Hex),
                        ("Cipher", str),
                        ("Key", str),
                        ("IV", str),
                       ],
                       result)
