#encoding:utf-8

import idaapi
import binascii
import ida_segment
import re
import ida_bytes
import idc
import ida_xref

# ADDR_SZ = 4 # Default: 32-bit
# if idaapi.get_inf_structure().is_64bit():
#     ADDR_SZ = 8

pcheader_MAGIC = 0xFFFFFFFA


def b2bin_search_str(magic_int):
    maigic_bin = magic_int.to_bytes(4,byteorder='little',signed=False)
    str_search = binascii.b2a_hex(maigic_bin).decode('utf-8')
    str_search = re.sub(r'''(?<=\w)(?=(?:\w\w)+$)'''," ",str_search)
    return str_search

def get_seg_name(addr):
    '''
    addr是int类型，先根据addr获取地址对应的segment的指针
    根据segment指针获取segment name
    '''
    seg_ptr = ida_segment.getseg(addr)
    return ida_segment.get_segm_name(seg_ptr,0)

def get_byte(addr,create:bool=True):
    '''
    增加create参数主要是为了ModuleData和PcHeader的初始函数中的parse参数
    如果parse参数为False，那么仅读取数据进行判断，而不修改数据类型
    '''
    data = ida_bytes.get_byte(addr)
    if create:
        ida_bytes.create_byte(addr,1,False)
    return data

def get_word(addr,create:bool=True):
    data = ida_bytes.get_word(addr)
    if create:
        ida_bytes.create_word(addr,2,False)
    return data

def get_dword(addr,create:bool=True):
    data = ida_bytes.get_dword(addr)
    if create:
        ida_bytes.create_dword(addr,4,False)
    return data

def get_qword(addr,create:bool=True):
    data = ida_bytes.get_qword(addr)
    if create:
        ida_bytes.create_qword(addr,8,False)
    return data

def int32(val:int):
    return int.from_bytes((val&0xffffffff).to_bytes(4,'little'),'little',signed=True)

def uint32(val:int):
    return int.from_bytes((val&0xffffffff).to_bytes(4,'little'),'little',signed=False)

def zig_zag_decode(val):
    return int32(-(val&1) ^ (val>>1))

def zig_zag_encode(val):
    return (val<<1) ^ (val>>31)

def zig_zag_encode64(val):
    return (val<<1) ^ (val>>63)

def read_varint(addr):
    val = 0
    shitf = 0
    while True:
        tmp = ida_bytes.get_byte(addr)
        addr += 1
        val |= (tmp&0x7f) << (shitf & 31)
        if tmp & 0x80 ==0:
            break
        shitf += 7
    return val

def read_pcvalue(addr):
    val = read_varint(addr)
    val = zig_zag_decode(val)
    val += -1
    return val

class slice():
    def __init__(self,addr,length,cap):
        self.addr = addr
        self.len = length
        self.cap = cap

    def __str__(self):
        return ("addr:0x%x len:0x%x cap:0x%x" % (self.addr,self.len,self.cap))


    def parse(start_addr,ptrsize,create:bool=True):
        '''
        增加create参数主要是为了ModuleData和pcHeader的初始函数中的parse参数
        如果parse参数为False，那么仅读取数据进行判断，而不修改数据类型
        '''
        addr = ida_bytes.get_qword(start_addr)
        length = ida_bytes.get_qword(start_addr + ptrsize)
        cap = ida_bytes.get_qword(start_addr + ptrsize * 2)
        if create:
            ida_bytes.create_qword(start_addr,ptrsize,False)
            ida_bytes.create_qword(start_addr + ptrsize,ptrsize,False)
            ida_bytes.create_qword(start_addr + ptrsize*2,ptrsize,False)

        return slice(addr,length,cap)

class String():
    def __init__(self,addr,length):
        self.addr = addr
        self.len = length

    def parse(start_addr,ptrsize,create:bool=True):
        addr = ida_bytes.get_qword(start_addr)
        length = ida_bytes.get_qword(start_addr+ptrsize)
        if create:
            ida_bytes.create_qword(start_addr,ptrsize,False)
            ida_bytes.create_qword(start_addr + ptrsize,ptrsize,False)
        return String(addr,length)

class bitvector():
    def __init__(self,n,bytedata):
        self.n = n
        self.bytedata = bytedata

    def parse(start_addr,create:bool=True):
        n = ida_bytes.get_dword(start_addr)
        bytedata = ida_bytes.get_qword(start_addr+8)
        if create:
            ida_bytes.create_dword(start_addr,4,False)
            ida_bytes.create_dword(start_addr+4,4,False)
            ida_bytes.set_cmt(start_addr+4,"pad",False)
            ida_bytes.create_qword(start_addr + 8,8,False)
        return bitvector(n,bytedata)


def find_addr(magic=pcheader_MAGIC):
    magic_str = b2bin_search_str(magic)
    ea = 0
    pcHeader_addrs = []
    while True:
        ea = idc.find_binary(ea+1,idc.SEARCH_DOWN,magic_str)
        if ea != idaapi.BADADDR:
            segname = get_seg_name(ea)
            if 'data' in segname:
                pcHeader_addrs.append({'segment':segname,'addr':ea,'ref_from':find_dref_to(ea)})
            continue
        else:
            break
    return pcHeader_addrs


def find_dref_to(addr):
    ref_from = []
    current = ida_xref.get_first_dref_to(addr)
    while True:
        if current != idaapi.BADADDR:
            ref_from.append(current)
            current = ida_xref.get_next_dref_to(addr,current)
        else:
            break
    return ref_from