import volatility.plugins.common as common
import volatility.commands as commands
import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import volatility.debug as debug


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


sshkeys_vtypes_64 = {
    '_sshcipher': [ 8, {
        "name": [0x0, ['pointer', ['String', dict(length = 64)]]],
    }],

    '_sshenc_61p1': [ 48, {
        "name": [0, ['pointer', ['String', dict(length = 64)]]],
        "cipher": [8, ['pointer', ['_sshcipher']]],
        "enabled": [16, ["int"]],
        "key_len": [20, ["unsigned int"]],
        "block_size": [24, ["unsigned int"]],
        "key": [32, ['pointer', ['array', lambda x: x.key_len, ["unsigned char"]]]],
        "iv": [40, ['pointer', ['array', lambda x: x.block_size, ["unsigned char"]]]],
    }],

    '_sshenc_61p2': [ 48, {
        "name": [0, ['pointer', ['String', dict(length = 64)]]],
        "cipher": [8, ['pointer', ['_sshcipher']]],
        "enabled": [16, ["int"]],
        "key_len": [20, ["unsigned int"]],
        "iv_len": [24, ["unsigned int"]],
        "block_size": [28, ["unsigned int"]],
        "key": [32, ['pointer', ['array', lambda x: x.key_len, ["unsigned char"]]]],
        "iv": [40, ['pointer', ['array', lambda x: x.iv_len, ["unsigned char"]]]],
    }],
}

sshkeys_vtypes_32 = {
    '_sshcipher': [ 4, {
        "name": [0x0, ['pointer32', ['String', dict(length = 64)]]],
    }],

    '_sshenc_61p1': [ 28, {
        "name": [0, ['pointer32', ['String', dict(length = 64)]]],
        "cipher": [4, ['pointer32', ['_sshcipher']]],
        "enabled": [8, ["int"]],
        "key_len": [12, ["unsigned int"]],
        "block_size": [16, ["unsigned int"]],
        "key": [20, ['pointer32', ['array', lambda x: x.key_len, ["unsigned char"]]]],
        "iv": [24, ['pointer32', ['array', lambda x: x.block_size, ["unsigned char"]]]],
    }],


    '_sshenc_61p2': [ 32, {
        "name": [0, ['pointer32', ['String', dict(length = 64)]]],
        "cipher": [4, ['pointer32', ['_sshcipher']]],
        "enabled": [8, ["int"]],
        "key_len": [12, ["unsigned int"]],
        "iv_len": [16, ["unsigned int"]],
        "block_size": [20, ["unsigned int"]],
        "key": [24, ['pointer32', ['array', lambda x: x.key_len, ["unsigned char"]]]],
        "iv": [28, ['pointer32', ['array', lambda x: x.iv_len, ["unsigned char"]]]],
    }],
}


class _sshenc_61p1(obj.CType):
    """A class for sshenc entries"""
    pass


class _sshenc_61p2(obj.CType):
    """A class for sshenc entries"""
    pass


class MemoryRegion(object):
    def __init__(self):
        self.start = None
        self.end = None
        self.permissions = None
        self.file_offset = None
        self.dev = None
        self.inode = None
        self.path = None


def dump_ctype(obj):
    d = {}
    for m in obj.members:
        #print m, type(m)
        val = getattr(obj, m)
        d[m] = val
    return d


class ScrapedKey(object):
    def __init__(self, task, sshenc, addr):
        self.task = task
        self.sshenc_addr = addr
        self.enc_name = None
        self.key = None
        self.iv = None
        self.sshenc = sshenc

    def __str__(self):        
        return "<Key enc_name={!r} sshenc_addr=0x{:x} key={} iv={} sshenc={} pid={}>".format(self.enc_name, self.sshenc_addr, self.key, self.iv, dump_ctype(self.sshenc), self.pid)

    def serialize(self, obj):
        if isinstance(obj, BaseStruct):
            return obj.getdict()
        return obj

    def as_json(self):
        d = dict(self.__dict__)
        return json.dumps(d, default=self.serialize)

    def __eq__(self, other):
        return self.task.pid == other.task.pid and self.sshenc_addr == other.sshenc_addr

    def __ne__(self, other):
        return not self.__eq__(self, other)


class SSHKeyExtractor(object):
    def __init__(self, task):
        self.task = task
        self.mem_maps = []
        self.proc_as = task.get_process_address_space()
        self.read_mem_map()
        self.update_as_types()

    def add_types(self, profile, vtypes, overlay = None):
        profile.vtypes.update(vtypes)
        if overlay:
            profile.merge_overlay(overlay)
        profile.compile()

    def update_as_types(self):
        if self.is_x64_proc():
            self.add_types(self.proc_as.profile, sshkeys_vtypes_64)
        else:
            self.add_types(self.proc_as.profile, sshkeys_vtypes_32)
        self.proc_as.profile.object_classes.update({"_sshenc_61p1": _sshenc_61p1, "_sshenc_61p2": _sshenc_61p2})

    def is_x64_proc(self):
        is_x64 = False
        for mr in self.mem_maps:
            if mr.end > 0xFFFFFFFF:                
                is_x64 = True
                break
        #print "ISX64", is_x64
        return is_x64

    def read_mem_map(self):
        maps = self.task.get_proc_maps()
        for vma in maps:
            (fname, major, minor, ino, pgoff) = vma.info(self.task)
            reg = MemoryRegion()
            reg.start = vma.vm_start
            reg.end = vma.vm_end
            reg.path = fname
            reg.file_offset = pgoff
            reg.inode = ino
            reg.permissions = vma.vm_flags
            self.mem_maps.append(reg)

    def probe_sshenc_block(self, ptr, sshenc_size):
        enc = obj.Object("_sshenc_61p2", vm = self.proc_as, offset = ptr)
        name_valid = enc.name.is_valid()
        cipher_valid = enc.cipher.is_valid()

        if not (name_valid and cipher_valid):
            return None

        enc_name = enc.name.dereference()
        enc_name = str(enc_name)       

        enc_properties = lookup_enc(enc_name)
        if not enc_properties:
            return None

        expected_key_len = enc_properties[2]
        key_len_valid = expected_key_len == enc.key_len
        if not key_len_valid:
            return None

        cipher_name = enc.cipher.name.dereference()
        cipher_name = str(cipher_name)
        if cipher_name != enc_name:
            return None

        debug.debug("Found possible candidate at address 0x{:x}.".format(ptr))

        #At this point we know pretty certain this is the sshenc struct. Let's figure out which version...
        expected_block_size = enc_properties[1]
        block_size_valid = expected_block_size == enc.block_size
        
        if not block_size_valid:
            debug.debug("Detected structure misaslignment. Trying sshenc_61p1 structure..")
            enc = obj.Object("_sshenc_61p1", vm = self.proc_as, offset = ptr)

        block_size_valid = expected_block_size == enc.block_size
        #print dump_ctype(enc), block_size_valid
        if not block_size_valid:
            debug.error("Detected sshenc structure but can't seem to align!")
            # !@# we can't seem to properly align the structure
            return None

        key_valid = enc.key.is_valid()
        iv_valid = enc.iv.is_valid()
        if key_valid and iv_valid:
            return enc

        debug.error("Detected sshenc structure but invalid key/IV address!")
        return None

    def read_char_array(self, arr):
        r = ""
        for d in arr:
            r += chr(d.v())
        return r

    def construct_scraped_key(self, ptr, enc):
        key = ScrapedKey(self.task, enc, ptr)
        key.enc_name = str(enc.name.dereference())
        key_raw = enc.key.dereference()
        key_raw_str = self.read_char_array(key_raw)
        key.key = key_raw_str.encode("hex")
        if isinstance(enc, _sshenc_61p1):
            iv_len = enc.block_size
        else:
            iv_len = enc.iv_len
        iv_raw = enc.iv.dereference()
        iv_raw_str = self.read_char_array(iv_raw)
        key.iv = iv_raw_str.encode("hex")
        return key

    def extract(self):
        sshenc_size = max(self.proc_as.profile.get_obj_size("_sshenc_61p1"), self.proc_as.profile.get_obj_size("_sshenc_61p2"))
        for region in self.mem_maps:            
            if region.path == "[heap]":
            #if True:
                ptr = region.start
                while ptr + sshenc_size < region.end:
                    if ptr % 0x10000 == 0:
                        debug.debug(">> {}".format(hex(ptr)))
                    sshenc = self.probe_sshenc_block(ptr, sshenc_size)
                    if sshenc:                        
                        key = self.construct_scraped_key(ptr, sshenc)
                        yield key
                    ptr += 4


class linux_sshkeys(linux_pslist.linux_pslist):
    """Dump OpenSSH Session Keys used to encrypt end to end traffic"""
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)      
        config.add_option('name', short_option = 'n', default = None, help = 'Operate on these Process names (comma-separated)', action = 'store', type = 'str')  

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        proc_name_list = []
        if self._config.name:
            proc_name_list = self._config.name.split(",")

        for task in tasks:
            if task.mm:                
                if len(proc_name_list) == 0 or task.comm in proc_name_list:
                    debug.debug("Scanning process: {} {} {}".format(task.pid, task.comm, task.get_commandline()))
                    extractor = SSHKeyExtractor(task)
                    keys = extractor.extract()
                    for key in keys:
                        yield key

    def generator(self, data):
        for key in data:
            task = key.task
            cmdline = task.get_commandline()
            yield (0, [task.comm, int(task.pid), int(task.parent.pid), int(task.uid), int(task.gid), cmdline, Address(key.sshenc_addr), key.key, key.iv])

    def unified_output(self, data):
        return TreeGrid([("Name", str),
                        ("Pid", int),
                        ("PPid", int),
                        ("Uid", int),
                        ("Gid", int),
                        ("Arguments", str),
                        ("Address", Address),
                        ("Key", str),
                        ("IV", str),
                       ],
                       self.generator(data))

    def render_text(self, outfd, data):
        banner = """
/\\____/\\
\\   (_)/        OpenSSH Session Key Dumper
 \\    X         By Jelle Vergeer
  \\  / \\
   \\/
"""
        outfd.write(banner)
        outfd.write("Scanning for OpenSSH sshenc structures...\n\n")
        self.table_header(outfd, [("Name","30"),
                                  ("Pid", "8"),
                                  ("PPid","8"),
                                  ("Address", "#018x"),
                                  ("Name", "30"),
                                  ("Key", "128"),
                                  ("IV", "64"),
                                 ]) 
        for key in data:
            task = key.task
            cmdline = task.get_commandline()
            name = "{} [{}]".format(task.comm, cmdline)
            #print name, task.pid, task.parent.pid, key.sshenc_addr, key.enc_name, key.key, key.iv
            self.table_row(outfd, name,
                task.pid,
                task.parent.pid,
                key.sshenc_addr,
                key.enc_name,
                key.key,
                key.iv,
            )
