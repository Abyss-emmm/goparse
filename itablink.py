#encoding:utf-8

import idaapi
import ida_bytes
idaapi.require('common')
idaapi.require('moduledata')

class ItabLinks():
    def __init__(self,start_addr,moduledata):
        self.start_addr = start_addr
        self.moduledata = moduledata
        ptrSize = moduledata.pcHeader.ptrSize
        self.itablinks_slice = common.slice.parse(start_addr,ptrSize)
        self.parsed_itabs = {}

        for i in range(0,self.itablinks_slice.len):
            itab_addr = common.get_qword(self.itablinks_slice.addr+i*ptrSize)
            self.parse_itab(itab_addr)
            
    
    def parse_itab(self,itab_addr):
        itab = Itab(itab_addr,self)
        self.parsed_itabs[itab_addr] = itab


class Itab():
    '''
    go 1.18.1
    Interface table
    Refer: https://golang.org/src/runtime/runtime2.go

    type itab struct {
        inter *interfacetype
        _type *_type
        hash  uint32 // copy of _type.hash. Used for type switches.
        _     [4]byte
        fun   [1]uintptr // variable sized. fun[0]==0 means _type does not implement inter.
    }
    '''
    def __init__(self,itab_addr,itablink:ItabLinks):
        self.start_addr = itab_addr
        self.itablink = itablink
        ptrSize = itablink.moduledata.pcHeader.ptrSize
        self.inter = common.get_qword(self.start_addr)
        self.type_addr = common.get_qword(self.start_addr+ptrSize)
        self.hash = common.get_dword(self.start_addr+ptrSize*2)
        common.get_dword(self.start_addr+ptrSize*2+4)#unused
        ida_bytes.set_cmt(self.start_addr+ptrSize*2,"hash",False)
        typelink = itablink.moduledata.typelinks
        if not typelink.has_parsed(self.inter):
            typelink.parse_type(self.inter)
        self.interface = typelink.parsed_types[self.inter]
        if not typelink.has_parsed(self.type_addr):
            typelink.parse_type(self.type_addr)
        self.funcs = []
        for i in range(self.interface.method_slice.len):
            func_addr = common.get_qword(self.start_addr+ptrSize*(3+i))
            if func_addr != 0:
                self.funcs.append(func_addr)
            else:
                break
        ida_bytes.set_cmt(self.start_addr+ptrSize*2+4,"Unused;Func num:%d,Interface num:%d" % (len(self.funcs),self.interface.method_slice.len),False)
