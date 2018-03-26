#!/usr/bin/env python

import ipaddress
import struct
import io
import time
import sys

if sys.version_info > (3,):
    long = int

class Node():
    def __init__(self):
        self.left = None
        self.right = None
        self.data = None
        self.data_schema = {}

        self.written_id = None

class Pointer():
    def __init__(self, addr):
        self.addr = addr

class DataCache():
    def __init__(self, addr):
        self.addr = addr

class EncoderConstants():
    TYPE_PTR = 1
    TYPE_UTF8STR = 2
    TYPE_DOUBLE = 3
    TYPE_BYTES = 4
    TYPE_UINT16 = 5
    TYPE_UINT32 = 6
    TYPE_MAP = 7
    TYPE_INT32 = 8
    TYPE_UINT64 = 9
    TYPE_UINT128 = 10
    TYPE_ARRAY = 11
    TYPE_DATACACHE = 12
    TYPE_ENDMARKER = 13
    TYPE_BOOLEAN = 14
    TYPE_FLOAT = 15

    key_map = {
        'ptr': TYPE_PTR,
        'utf8-string': TYPE_UTF8STR,
        'double': TYPE_DOUBLE,
        'bytes': TYPE_BYTES,
        'uint16': TYPE_UINT16,
        'uint32': TYPE_UINT32,
        'map': TYPE_MAP,
        'int32': TYPE_INT32,
        'uint64': TYPE_UINT64,
        'uint128': TYPE_UINT128,
        'array': TYPE_ARRAY,
        'data_cache': TYPE_DATACACHE,
        'end_marker': TYPE_ENDMARKER,
        'boolean': TYPE_BOOLEAN,
        'float': TYPE_FLOAT
    }

class Encoder():

    def __init__(self,
        ip_version,
        record_size,
        database_type,
        languages,
        description,
        compat=True):
        
        if ip_version != 4 and ip_version != 6:
            raise Exception('Encoder: __new__: %d is not a correct IP version (4 or 6)' % ip_version)

        self.ip_version = ip_version
        self.record_size = record_size
        self.database_type = database_type
        self.languages = languages
        self.description = description
        self.node_count = 1
        self.entries_count = 0
        self.trie = Node()
        self.data = []
        self.data_serialized = []
        self.data_pos = [ 0 ]
        self.compat = compat

    @staticmethod
    def ipnet_to_bits(ipnet):
        ipnum = int(ipnet.network_address)
        
        m = ipnet.max_prefixlen
        arr = []

        for i in range(0, m/8):
            val = (ipnum&(0xff<<(m-(i+1)*8)))>>(m-(i+1)*8)
            arr.append(int(val))

        cutsize = ipnet.prefixlen/8 + int(ipnet.prefixlen%8 != 0)
        return arr[0:cutsize]

    def _add_to_trie(self, ipnum, prefixlen, max_prefixlen, keyid, strict = True, last=False):        
        curnode = self.trie
        parentnode = None

        carrydata = None
        for i in range(0, prefixlen):
            val = int((ipnum&(0x1<<(max_prefixlen-(i+1))))>>(max_prefixlen-(i+1)))

            parentnode = curnode
            if val == 0:
                curnode = curnode.left
            elif val == 1:
                curnode = curnode.right

            if curnode == None:
                curnode = Node()

                if i < prefixlen-1:
                    self.node_count += 1
                if val == 0:
                    parentnode.left = curnode
                elif val == 1:
                    parentnode.right = curnode
            
            if curnode.data != None and i < prefixlen-1 and strict:
                raise Exception('Encoder: add_to_trie: try setting data on a non-final: %s already has child. Not updating in strict mode.' % ipnum)
            elif curnode.data != None and i < prefixlen-1 and carrydata == None:
                carrydata = curnode.data
                curnode.data = None
                self.node_count += 1
            elif carrydata != None and i <= prefixlen-1:
                curnode.data = None
                if val == 0:
                    carrynode = Node()
                    carrynode.data = carrydata
                    parentnode.right = carrynode
                elif val == 1:
                    carrynode = Node()
                    carrynode.data = carrydata
                    parentnode.left = carrynode

            if i == prefixlen-1:
                if curnode.data is not None and strict:
                    raise Exception('Encoder: add_to_trie: node %s already has data. Not updating in strict mode.' % ipnum)

                if (curnode.left is not None or curnode.right is not None) and strict:
                    raise Exception('Encoder: add_to_trie: try setting data on a non-final: %s already has child. Not updating in strict mode.' % ipnum)

                if not strict and (curnode.left is not None or curnode.right is not None):
                    if curnode.left is not None:
                        newipnum = ipnum | 1<<(max_prefixlen-i-2)
                        self._add_to_trie(newipnum, prefixlen+1, max_prefixlen, keyid, strict, last=True)
                    if curnode.right is not None:
                        newipnum = ipnum
                        self._add_to_trie(newipnum, prefixlen+1, max_prefixlen, keyid, strict, last=True)
                elif curnode.data is None or not last: # Fixme: cannot change me otherwise
                    curnode.data = keyid

    def add_to_trie(self, ipnet, keyid, strict = True):
        ipnum = int(ipnet.network_address)
        m = ipnet.max_prefixlen
        ipnet.prefixlen
        self._add_to_trie(ipnum, ipnet.prefixlen, ipnet.max_prefixlen, keyid, strict)

    def add_data(self, d):
        self.data.append(d)

        buf = io.BytesIO()
        size = Encoder.write_data_single(buf, d)
        self.data_serialized.append(buf)
        self.data_pos.append( self.data_pos[-1] + size )
        return self.data_pos[-2]

    def insert_raw_data(self, data):
        data_offset = self.add_data(data)
        return data_offset

    def insert_data(self, data):
        data_struct = Encoder.python_data_to_mmdb_struct(data)
        data_offset = self.add_data(data_struct)
        return data_offset

    def insert_network(self, prefix, data_offset, strict = True):
        self.entries_count += 1
        ipnet = ipaddress.ip_network(prefix, strict=False)

        if ipnet.version == 6 and self.ip_version != 6:
            raise Exception('Encoder: insert_network: cannot add IPv6 address in IPv4 table')

        if ipnet.version == 4 and self.ip_version == 6:
            base4in6 = ipaddress.IPv6Address(u'::ffff:0:0')
            v4in6addr = ipaddress.IPv6Address(int(ipnet.network_address)+int(base4in6))

            # Maxmind DBs skips the first 96 bits (do not include the 0xffff)
            if self.compat:
                v4in6addr = ipaddress.IPv6Address(int(ipnet.network_address))

            v4in6addr_plen = ipnet.prefixlen + 96
            ipnet = ipaddress.IPv6Network(u'{}/{}'.format(str(v4in6addr), v4in6addr_plen), strict=False)

        #print(ipnet)
        self.add_to_trie(ipnet, data_offset, strict=strict)

    @staticmethod
    def encode_single_ptrs(record_size, ptr):
        isnotmod8 = (record_size%8 != 0)
        ptr_list = []

        m = record_size

        shift = 0
        if isnotmod8:
            shift = 4

        for i in range(0, int(m/8)):
            #print("{} {} {}".format(i, m, 0xff<<(m-(i+1)*8)))
            ptr_list.append(int((ptr&(0xff<<(m - (i+1)*8 - shift)))>>(m - (i+1)*8 - shift)))
        return ptr_list

    @staticmethod
    def encode_ptrs(record_size, ptrleft, ptrright):
        ptrs = []
        isnotmod8 = (record_size%8 != 0)
        if record_size%4 != 0:
            raise Exception('Encoder: encode_ptrs: must have a size which can be modulo 4. Got %d.' % record_size)

        ptrleft_list = Encoder.encode_single_ptrs(record_size, ptrleft)
        ptrright_list = Encoder.encode_single_ptrs(record_size, ptrright)
        middle = []
        if isnotmod8:
            middle.append(
                    int(
                        (ptrleft&(0xf<<(record_size-4)))>>(record_size-8)
                        |
                        (ptrright&(0xf<<(record_size-4)))>>(record_size-4)
                        )
                )

        ptrs = ptrleft_list + middle + ptrright_list
        return ptrs

    @staticmethod
    def write_node(buf, record_size, ptrleft, ptrright):
        chars = Encoder.encode_ptrs(record_size, ptrleft, ptrright)
        #print("Writing node {} ({}) -> {} -> {}. Data {}".format(node, node.written_id, ptrleft, ptrright, node.data))
        for i in chars:
            Encoder._write_v(buf, i)

    @staticmethod
    def write_nodes(buf, node_count, record_size, firstnode, datafirst = False):
        cur_id = 0
        firstnode.written_id = cur_id

        toexplore = [ firstnode ]
        itera = 0
        while True:
            future_id_left = node_count
            future_id_right = node_count

            if len(toexplore) > 0:
                #print(toexplore)
                curnode = toexplore.pop(0)

                if curnode.left != None:
                    if curnode.left.data != None:
                        future_id_left = curnode.left.data + 16 + node_count
                    else:
                        cur_id += 1
                        future_id_left = cur_id
                        curnode.left.written_id = future_id_left

                        toexplore.append(curnode.left)
                    #print("appending left {} -> {}".format(curnode, curnode.left))

                if curnode.right != None:
                    if curnode.right.data != None:
                        future_id_right = curnode.right.data + 16 + node_count
                    else:
                        cur_id += 1
                        future_id_right = cur_id
                        curnode.right.written_id = future_id_right

                        toexplore.append(curnode.right)
                    #print("appending right {} -> {}".format(curnode, curnode.right))
                #print('{} -> {} ({} {} {}) ({} {})'.format(itera, curnode, curnode.left, curnode.right, curnode.data, future_id_left, future_id_right))
                Encoder.write_node(buf, record_size, future_id_left, future_id_right)
                itera += 1
            else:
                break

    @staticmethod
    def write_separator(buf):
        for i in range(0, 16):
            Encoder._write_v(buf, 0)

    @staticmethod
    def _write_v(buf, d):
        if type(d) is int:
            d = bytearray((d,))
        if type(d) is str and sys.version_info > (3,):
            d = d.encode('utf-8')
        return buf.write(d) 

    @staticmethod
    def write_field(buf, fieldid, value):
        length = 0
        fieldid_write = fieldid

        written = 0

        content = []

        if fieldid == EncoderConstants.TYPE_MAP or fieldid == EncoderConstants.TYPE_ARRAY or fieldid == EncoderConstants.TYPE_UTF8STR:
            length = len(value)
            if fieldid == EncoderConstants.TYPE_UTF8STR:
                content = value
        elif fieldid == EncoderConstants.TYPE_BOOLEAN:
            length = int(value)
        elif fieldid == EncoderConstants.TYPE_FLOAT:
            length = 4
            content = struct.pack('>f', value)
        elif fieldid == EncoderConstants.TYPE_DOUBLE:
            length = 8
            content = struct.pack('>d', value)
        elif fieldid == EncoderConstants.TYPE_UINT16 or fieldid == EncoderConstants.TYPE_UINT32:
            length = 4
            content = struct.pack('>I', value)
        elif fieldid == EncoderConstants.TYPE_INT32:
            length = 4
            content = struct.pack('>i', value)
        elif fieldid == EncoderConstants.TYPE_UINT64:
            length = 8
            content = struct.pack('>Q', value)
        elif fieldid == EncoderConstants.TYPE_UINT128:
            raise Exception('Encoder: write_field: 128 bits unsigned integers encoding not implemented')
        elif fieldid == EncoderConstants.TYPE_PTR:
            length = 3<<3
            content = struct.pack('>I', value.addr)
        elif fieldid == EncoderConstants.TYPE_DATACACHE:
            raise Exception('Encoder: write_field: data cache container encoding not implemented')
        else:
            raise Exception('Encoder: write_field: %d encoding not implemented' % fieldid)

        if fieldid == EncoderConstants.TYPE_UINT16:
            length = 2
            content = content[len(content)-2:]

        if fieldid > 7:
            fieldid_write = 0

        length_mod = length
        if length >= 65821:
            length_mod = 31
        elif length >= 285:
            length_mod = 30
        elif length >= 29:
            length_mod = 29

        tow = length_mod&0x1f | (fieldid_write&0x7)<<5
        Encoder._write_v(buf, tow)
        written += 1
        
        if length >= 65821:
            Encoder._write_v(buf, (length - 65821)>>16&0xff)
            Encoder._write_v(buf, (length - 65821)>>8&0xff)
            Encoder._write_v(buf, (length - 65821)&0xff)
            written += 3
        elif length >= 285:
            Encoder._write_v(buf, (length - 285)>>8&0xff)
            Encoder._write_v(buf, (length - 285)&0xff)
            written += 2
        elif length >= 29:
            Encoder._write_v(buf, length - 29)
            written += 1 # When writing on a file, doesn't return anything

        if fieldid > 7:
            tow = fieldid-7
            Encoder._write_v(buf, tow)
            written += 1

        if fieldid == EncoderConstants.TYPE_MAP:
            if type(value) is not dict:
                raise Exception('Encoder: write_field: encountered not a map')

            for k,v in value.items():
                written += Encoder.write_field(buf, EncoderConstants.TYPE_UTF8STR, k)
                written += Encoder.write_data_single(buf, v)

        elif fieldid == EncoderConstants.TYPE_ARRAY:
            if type(value) is not list:
                raise Exception('Encoder: write_field: encountered not a map')

            for v in value:
                written += Encoder.write_data_single(buf, v)

        else:
            if sys.version_info > (3,):
                Encoder._write_v(buf, content)
                written += len(content)
            else:
                for i in content:
                    Encoder._write_v(buf, i)
                    written += 1

        return written

    @staticmethod
    def write_data_single(buf, data):
        written = 0
        if data != None and 'type' in data:
            vtype = data['type']
            if vtype in EncoderConstants.key_map:
                fieldid = EncoderConstants.key_map[vtype]
                value = None

                if not vtype == EncoderConstants.TYPE_ENDMARKER and 'content' not in data:
                    raise Exception('Encoder: write_data: data must have a \'content\' key')

                value = data['content']
                written += Encoder.write_field(buf, fieldid, value)
            else:
                raise Exception('Encoder: write_data: type %s unknown' % vtype)
        else:
            raise Exception('Encoder: write_data: data must have a \'type\' key')

        return written

    @staticmethod
    def write_data_serialized(buf, data_serialized):
        for curdata in data_serialized:
            Encoder._write_v(buf, curdata.getvalue())

    @staticmethod
    def write_data(buf, data):
        for curdata in data:
            Encoder.write_data_single(buf, curdata)

    @staticmethod
    def write_meta(buf, node_count, record_size, ip_version, database_type, languages, description):
        buf.write(b'\xab\xcd\xefMaxMind.com')
        Encoder.write_field(buf, EncoderConstants.TYPE_MAP, 
                {'node_count':
                    {'type': 'uint32',
                     'content': node_count},
                'record_size':
                    {'type': 'uint16',
                     'content': record_size},
                'ip_version':
                    {'type': 'uint16',
                     'content': ip_version},
                'database_type':
                    {'type': 'utf8-string',
                     'content': database_type},
                'description': Encoder.python_data_to_mmdb_struct(description),
                'languages': Encoder.python_data_to_mmdb_struct(languages),
                'binary_format_major_version':
                    {'type': 'uint16',
                     'content': 2},
                'binary_format_minor_version':
                    {'type': 'uint16',
                     'content': 0},
                'build_epoch':
                    {'type': 'uint64',
                     'content': long(time.time())},
                }
            )

    @staticmethod
    def python_data_to_mmdb_struct(data):
        newstruct = {'type': None, 'content': None}
        if type(data) is dict:
            newstruct['type'] = 'map'
            newstruct['content'] = {}
            for k,v in data.items():
                newstruct['content'][k] = Encoder.python_data_to_mmdb_struct(v)
        elif type(data) is list:
            newstruct['type'] = 'array'
            newstruct['content'] = []
            for v in data:
                newstruct['content'].append(Encoder.python_data_to_mmdb_struct(v))
        elif type(data) is int:
            newstruct['type'] = 'uint32'
            newstruct['content'] = data
        elif type(data) is long:
            newstruct['type'] = 'uint64'
            newstruct['content'] = data
        elif type(data) is float:
            newstruct['type'] = 'float'
            newstruct['content'] = data
        elif type(data) is str:
            newstruct['type'] = 'utf8-string'
            newstruct['content'] = data
        elif data.__class__ is Pointer:
            newstruct['type'] = 'ptr'
            newstruct['content'] = data
        elif data.__class__ is DataCache:
            newstruct['type'] = 'data_cache'
            newstruct['content'] = data
        else:
            raise Exception('Encoder: python_data_to_mmdb_struct: could not convert type {}'.format(type(data)))
        return newstruct

    def write(self, buf):
        if hasattr(buf, 'write'):
            Encoder.write_nodes(buf, self.node_count, self.record_size, self.trie)
            Encoder.write_separator(buf)
            Encoder.write_data_serialized(buf, self.data_serialized)
            Encoder.write_meta(buf, self.node_count, self.record_size, self.ip_version, self.database_type, self.languages, self.description)
        else:
            raise Exception('Encoder: write: no write method. Is the object a buffer?')

    def write_file(self, filename):
        with open(filename, 'wb') as f:
            self.write(f)
