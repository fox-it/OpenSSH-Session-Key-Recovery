from __future__ import print_function
import sys
import os
import ctypes
import binascii
from ptrace.debugger import PtraceDebugger
import logging
import psutil
import json
import re
import inspect
import time
import traceback
import resource
from ctypes import POINTER, Structure, c_uint, c_char_p, c_int, sizeof


log = logging.getLogger(__package__)

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


def props(obj):
    pr = {}
    for name in dir(obj):
        value = getattr(obj, name)
        if not name.startswith('_') and not inspect.ismethod(value) and not inspect.isbuiltin(value):
            pr[name] = value
    return pr


class ScrapedKey(object):
    def __init__(self, pid, proc_name, sshenc, addr):
        self.pid = pid
        self.proc_name = proc_name
        self.sshenc_addr = addr
        self.cipher_name = None
        self.key = None
        self.iv = None
        self.sshenc = sshenc
        self.network_connections = []

    def __str__(self):        
        return "<Key cipher_name={!r} sshenc_addr=0x{:x} key={} iv={} sshenc={} pid={}>".format(self.cipher_name, self.sshenc_addr, self.key, self.iv, self.sshenc, self.pid)

    def serialize(self, obj):
        if isinstance(obj, BaseStruct):
            return obj.getdict()
        return obj

    def serial_network_connections(self):
        ret = []
        for con in self.network_connections:
            con_dict = props(con)
            #print con_dict
            ret.append(con_dict)
        return ret

    def as_json(self):
        d = dict(self.__dict__)
        d['network_connections'] = self.serial_network_connections()
        return json.dumps(d, default=self.serialize)

    def __eq__(self, other):
        return self.pid == other.pid and self.sshenc_addr == other.sshenc_addr

    def __ne__(self, other):
        return not self.__eq__(self, other)


class BaseStruct(ctypes.Structure):
    def __str__(self):
        values = []
        for field in self._fields_:
            name = field[0]
            val = getattr(self, name)            
            if isinstance(val, (str, )):
                val = repr(val)
            if isinstance(val, (int, )):
                val = hex(val)
            values.append("{}={}".format(name, val))

        return "<{} {}>".format(self.__class__.__name__, " ".join(values))

    def getdict(struct):
        return dict((field, getattr(struct, field)) for field, _ in struct._fields_)


class sshcipher(BaseStruct):
    _fields_ = [
        ("name", ctypes.c_void_p),
        #("block_size", ctypes.c_uint),
        #("key_len", ctypes.c_uint),
        #("iv_len", ctypes.c_uint),
        #("auth_len", ctypes.c_uint),
        #("flags", ctypes.c_uint),
    ]


"""
<= openssh-6.1p1
struct Enc {
    char    *name;
    Cipher  *cipher;
    int enabled;
    u_int   key_len;
    u_int   block_size;
    u_char  *key;
    u_char  *iv;
};
>= openssh-6.2p1
struct Enc {
    char    *name;
    Cipher  *cipher;
    int enabled;
    u_int   key_len;
    u_int   iv_len;
    u_int   block_size;
    u_char  *key;
    u_char  *iv;
};
"""

class sshenc_61p1(BaseStruct):  
    _fields_ = [
        ("name", ctypes.c_void_p),
        ("cipher", ctypes.c_void_p),
        ("enabled", ctypes.c_int),
        ("key_len", ctypes.c_uint),
        #("iv_len", ctypes.c_uint),
        ("block_size", ctypes.c_uint),
        ("key", ctypes.c_void_p),
        ("iv", ctypes.c_void_p),
    ]

class sshenc_62p1(BaseStruct):  
    _fields_ = [
        ("name", ctypes.c_void_p),
        ("cipher", ctypes.c_void_p),
        ("enabled", ctypes.c_int),
        ("key_len", ctypes.c_uint),
        ("iv_len", ctypes.c_uint),
        ("block_size", ctypes.c_uint),
        ("key", ctypes.c_void_p),
        ("iv", ctypes.c_void_p),
    ]

class sshmac(BaseStruct):
    _fields_ = [
        ("name", ctypes.c_void_p),
        ("enabled", ctypes.c_int),
        ("mac_len", ctypes.c_uint),
        ("key", ctypes.c_void_p),
        ("key_len", ctypes.c_uint),
        ("type", ctypes.c_int),
        ("etm", ctypes.c_int),
        ("hmac_ctx", ctypes.c_void_p),
        ("umac_ctx", ctypes.c_void_p),
    ]


class sshcomp(BaseStruct):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("enabled", ctypes.c_int),
        ("name", ctypes.c_void_p),
    ]




class MemoryRegion(object):
    def __init__(self, values):
        self.start = int(values[0], 16)
        self.end = int(values[1], 16)
        self.permissions = values[2]
        self.file_offset = int(values[3], 16)
        self.dev = values[4]
        self.inode = values[5]
        self.path = values[6]


class SSHKeyExtractor(object):
    def __init__(self, pid):
        self.dbg = PtraceDebugger()
        self.pid = pid
        self.proc = psutil.Process(pid)
        self.network_connections = self.proc.connections()
        self.dbg_proc = None
        self.heap_map_info = None
        self.mem_maps = None

    def __repr__(self):
        return "<SSHKeyExtractor: {}>".format(self.pid)

    def _get_mem_maps(self):
        mem_map = open("/proc/{}/maps".format(self.pid)).read()
        for line in mem_map.splitlines():
            regex = r"(\w+)-(\w+)\ ([\w\-]+) (\w+) ([\w\:]+) (\w+) +(.*)"
            match = re.search(regex, line)
            yield MemoryRegion(match.groups())           

    def _get_heap_map_info(self):
        #print repr(self.mem_maps)
        for mem_map in self.mem_maps:
            if mem_map.path == "[heap]":
                return mem_map
        return None

    def is_valid_ptr(self, ptr, allow_nullptr=True, heap_only=True):
        if (ptr == 0 or ptr is None):
            if allow_nullptr:
                return True
            else:
                return False        

        if heap_only:
            return ptr >= self.heap_map_info.start and ptr < self.heap_map_info.end
        
        for mem_map in self.mem_maps:
            valid = ptr >= mem_map.start and ptr < mem_map.end
            if valid:
                return True
        return False

    def lookup_enc(self, name):
        return OPENSSH_ENC_ALGS_LOOKUP.get(name, None)

    def read_string(self, ptr, length):
        val = self.dbg_proc.readCString(ptr, length)
        if val:
            return val[0].decode("utf-8", errors="ignore")
        return None

    def probe_sshenc_block(self, ptr, sshenc_size):
        """
            char    *name ;             0x808e8a4 -> "chacha20-poly1305@openssh.com"
            Cipher  *cipher;            0x808e6d0 Cipher{name=0x80989e4 -> "chacha20-poly1305@openssh.com"}
            int enabled;                0
            u_int   key_len;            8-64
            *u_int   iv_len;            12
            u_int   block_size;         8-16
            u_char  *key;               0x80989e4 -> "6e4a242303346ecd60209e41b03c438b"
            u_char  *iv;                0x8088f4e -> "7e59454fbe2247d52d29bd373c3f53ae"
        """
        mem = self.dbg_proc.readBytes(ptr, sshenc_size)  
        enc = sshenc_62p1.from_buffer_copy(mem)
        sshenc_name = self.is_valid_ptr(enc.name, allow_nullptr=False)
        sshenc_cipher = self.is_valid_ptr(enc.cipher, allow_nullptr=False, heap_only=False)

        if not (sshenc_name and sshenc_cipher):
            return None

        name_str = self.read_string(enc.name, 64)
        enc_properties = self.lookup_enc(name_str)
        #print(repr(name_str), enc_properties)
        if not enc_properties:
            return None        

        expected_key_len = enc_properties[2]
        key_len_valid = expected_key_len == enc.key_len
        if not key_len_valid:
            return None
                
        cipher = self.dbg_proc.readStruct(enc.cipher, sshcipher)
        cipher_name_valid = self.is_valid_ptr(cipher.name, allow_nullptr=False, heap_only=False)                
        if not cipher_name_valid:
            return None

        cipher_name = self.read_string(cipher.name, 64)
        if cipher_name != name_str:
            return None        

        #print(cipher_name)
        #At this point we know pretty certain this is the sshenc struct. Let's figure out which version...
        expected_block_size = enc_properties[1]
        block_size_valid = expected_block_size == enc.block_size
        if not block_size_valid:
            enc = sshenc_61p1.from_buffer_copy(mem)

        block_size_valid = expected_block_size == enc.block_size
        if not block_size_valid:
            # !@#$ we can't seem to properly align the structure
            return None

        sshenc_key = self.is_valid_ptr(enc.key, allow_nullptr=False)
        sshenc_iv = self.is_valid_ptr(enc.iv, allow_nullptr=False)
        if sshenc_iv and sshenc_key:
            return enc
        return None    

    def construct_scraped_key(self, ptr, enc):
        key = ScrapedKey(self.pid, self.proc.name(), enc, ptr)
        key.network_connections = self.network_connections
        key.cipher_name = self.read_string(enc.name, 64)
        key_raw = self.dbg_proc.readBytes(enc.key, enc.key_len)
        key.key = key_raw.hex()
        if isinstance(enc, sshenc_61p1):
            iv_len = enc.block_size
        else:
            iv_len = enc.iv_len
        iv_raw = self.dbg_proc.readBytes(enc.iv, iv_len)
        key.iv = iv_raw.hex()
        return key

    def align_size(self, size, multiple):
        add = multiple - (size % multiple)
        return size + add

    def extract(self, known_addr=None):
        known_addr = known_addr or []
        ret = []
        self.dbg_proc = self.dbg.addProcess(self.pid, False)
        self.dbg_proc.cont()
        self.mem_maps = list(self._get_mem_maps())
        self.heap_map_info = self._get_heap_map_info()        
        ptr = self.heap_map_info.start
        sshenc_size = max(sizeof(sshenc_61p1), sizeof(sshenc_62p1))
        while ptr + sshenc_size < self.heap_map_info.end:
            if ptr in known_addr:
                sshenc_aligned_size = self.align_size(sshenc_size, 4)
                ptr += sshenc_aligned_size
                #print 'skip 0x{:x}, {}'.format(ptr, sshenc_aligned_size)
                continue
            sshenc = self.probe_sshenc_block(ptr, sshenc_size)
            if sshenc:
                key = self.construct_scraped_key(ptr, sshenc)
                ret.append(key)
            ptr += 4
        return ret

    def cleanup(self):
        if self.dbg_proc:
            from signal import SIGTRAP, SIGSTOP, SIGKILL
            if self.dbg_proc.read_mem_file:
                self.dbg_proc.read_mem_file.close()
            self.dbg_proc.kill(SIGSTOP)
            self.dbg_proc.waitSignals(SIGTRAP, SIGSTOP)
            self.dbg_proc.detach()
        if self.dbg:
            self.dbg.deleteProcess(self.dbg_proc)
            self.dbg.quit()
        del self.dbg_proc
        del self.dbg
        self.proc = None



def print_file_limit():
    print("getrlimit:{}".format(resource.getrlimit(resource.RLIMIT_NOFILE)), file=sys.stderr)


def configure_file_limit(limit):
    print_file_limit()
    resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))
    print_file_limit()


def main():
    configure_file_limit(4096)
    #logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
    found_keys = {} #pid, ScapedKey
    key_addresses = {} #pid, MemoryAddress (int)
    while True:
        procs = psutil.process_iter()
        for proc in procs:
            if proc.name() in ["ssh", "sshd"]:
                if proc.pid not in found_keys:
                    found_keys[proc.pid] = [ ]
                if proc.pid not in key_addresses:
                    key_addresses[proc.pid] = [ ]

                #print "trying {}".format(proc)
                known_addr = key_addresses[proc.pid]
                extractor = SSHKeyExtractor(proc.pid)                
                keys = False
                try:
                    keys = extractor.extract(known_addr=known_addr)
                    found_keys[proc.pid].extend(keys)
                    for key in keys:
                        key_addresses[proc.pid].append(key.sshenc_addr)
                        print(key.as_json())
                        #print "Found sshenc structure at 0x{:x}. Algorithm: '{}' Key: '{}', IV: '{}'.".format(key.sshenc_addr, key.cipher_name, key.key, key.iv)
                except Exception as e:
                    print(e, file=sys.stderr)
                    print(traceback.format_exc(), file=sys.stderr)
                extractor.cleanup()
                del extractor
        time.sleep(8)


if __name__ == '__main__':
    main()
