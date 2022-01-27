#encoding:utf-8
import ida_bytes
import idaapi
from typelink import RType
idaapi.require('pcHeader')
idaapi.require('common')
idaapi.require('typelink')
idaapi.require('itablink')


class ModuleData():

    def __init__(self,start_addr,parse:bool=True):
        '''
        go 1.16.8
        src\runtime\symtab.go
        type moduledata struct {
            pcHeader     *pcHeader
            funcnametab  []byte
            cutab        []uint32
            filetab      []byte
            pctab        []byte
            pclntable    []byte
            ftab         []functab
            findfunctab  uintptr
            minpc, maxpc uintptr

            text, etext           uintptr
            noptrdata, enoptrdata uintptr
            data, edata           uintptr
            bss, ebss             uintptr
            noptrbss, enoptrbss   uintptr
            end, gcdata, gcbss    uintptr
            types, etypes         uintptr

            textsectmap []textsect
            typelinks   []int32 // offsets from types
            itablinks   []*itab

            ptab []ptabEntry

            pluginpath string
            pkghashes  []modulehash

            modulename   string
            modulehashes []modulehash

            hasmain uint8 // 1 if module contains the main function, 0 otherwise

            gcdatamask, gcbssmask bitvector

            typemap map[typeOff]*_type // offset to *_rtype in previous module

            bad bool // module failed to load and should be ignored

            next *moduledata
        }
        增加parse参数，主要是为了仅读取数据，而不解析，用于寻找firstmodule和pcheader时进行数据比较，
        而不影响数据类型
        '''
        self.start_addr = start_addr
        self.pcHeader_addr = ida_bytes.get_qword(start_addr)
        if parse:
            self.pcHeader = pcHeader.pcHeader(self.pcHeader_addr,self.start_addr)
            ptrSize = self.pcHeader.ptrSize
        else:
            ptrSize = 8
        self.funcname = common.slice.parse(start_addr+ptrSize,ptrSize,parse)
        self.cutab = common.slice.parse(start_addr+ptrSize*4,ptrSize,parse)
        self.filetab = common.slice.parse(start_addr+ptrSize*7,ptrSize,parse)
        self.pctab = common.slice.parse(start_addr+ptrSize*10,ptrSize,parse)
        self.pclntable = common.slice.parse(start_addr+ptrSize*13,ptrSize,parse)
        self.ftab = common.slice.parse(start_addr+ptrSize*16,ptrSize,parse)

        if parse:
            self.findfunctab = ida_bytes.get_qword(start_addr+ptrSize*19)
            ida_bytes.set_cmt(start_addr+ptrSize*19,'findfunctab',False)
            self.minpc = ida_bytes.get_qword(start_addr+ptrSize*20)
            ida_bytes.set_cmt(start_addr+ptrSize*20,'minpc',False)
            self.maxpc = ida_bytes.get_qword(start_addr+ptrSize*21)
            ida_bytes.set_cmt(start_addr+ptrSize*21,'maxpc',False)
            self.text = ida_bytes.get_qword(start_addr+ptrSize*22)
            ida_bytes.set_cmt(start_addr+ptrSize*22,'text',False)
            self.etext = ida_bytes.get_qword(start_addr+ptrSize*23)
            ida_bytes.set_cmt(start_addr+ptrSize*23,'etext',False)
            self.noptrdata = ida_bytes.get_qword(start_addr+ptrSize*24)
            ida_bytes.set_cmt(start_addr+ptrSize*24,'noptrdata',False)
            self.enoptrdata = ida_bytes.get_qword(start_addr+ptrSize*25)
            ida_bytes.set_cmt(start_addr+ptrSize*25,'enoptrdata',False)
            self.data = ida_bytes.get_qword(start_addr+ptrSize*26)
            ida_bytes.set_cmt(start_addr+ptrSize*26,'data',False)
            self.edata = ida_bytes.get_qword(start_addr+ptrSize*27)
            ida_bytes.set_cmt(start_addr+ptrSize*27,'edata',False)
            self.bss = ida_bytes.get_qword(start_addr+ptrSize*28)
            ida_bytes.set_cmt(start_addr+ptrSize*28,'bss',False)
            self.ebss = ida_bytes.get_qword(start_addr+ptrSize*29)
            ida_bytes.set_cmt(start_addr+ptrSize*29,'ebss',False)
            self.noptrbss = ida_bytes.get_qword(start_addr+ptrSize*30)
            ida_bytes.set_cmt(start_addr+ptrSize*30,'noptrbss',False)
            self.enoptrbss = ida_bytes.get_qword(start_addr+ptrSize*31)
            ida_bytes.set_cmt(start_addr+ptrSize*31,'enoptrbss',False)
            self.end = ida_bytes.get_qword(start_addr+ptrSize*32)
            ida_bytes.set_cmt(start_addr+ptrSize*32,'end',False)
            self.gcdata = ida_bytes.get_qword(start_addr+ptrSize*33)
            ida_bytes.set_cmt(start_addr+ptrSize*33,'gcdata',False)
            self.gcbss = ida_bytes.get_qword(start_addr+ptrSize*34)
            ida_bytes.set_cmt(start_addr+ptrSize*34,'gcbss',False)
            self.types = ida_bytes.get_qword(start_addr+ptrSize*35)
            ida_bytes.set_cmt(start_addr+ptrSize*35,'types',False)
            self.etypes = ida_bytes.get_qword(start_addr+ptrSize*36)
            ida_bytes.set_cmt(start_addr+ptrSize*36,'etypes',False)    
            self.textsectmap = common.slice.parse(start_addr+ptrSize*37,ptrSize)
            self.typelinks = typelink.TypeLinks(start_addr+ptrSize*40,self)
            ida_bytes.set_cmt(start_addr+ptrSize*40,'typelinks',False)
            self.itablinks = itablink.ItabLinks(start_addr+ptrSize*43,self)
            ida_bytes.set_cmt(start_addr+ptrSize*43,"itablinks",False)
            self.ptab = common.slice.parse(start_addr+ptrSize*46,ptrSize)
            ida_bytes.set_cmt(start_addr+ptrSize*46,'ptab',False)
            self.pluginpath = common.String.parse(start_addr+ptrSize*49,ptrSize)
            ida_bytes.set_cmt(start_addr+ptrSize*49,'pluginpath',False)
            self.pkghashes = common.slice.parse(start_addr+ptrSize*51,ptrSize)
            ida_bytes.set_cmt(start_addr+ptrSize*51,'pkghashes',False)
            self.modulename = common.String.parse(start_addr+ptrSize*54,ptrSize)
            ida_bytes.set_cmt(start_addr+ptrSize*54,'modulename',False)
            self.modulehashes = common.slice.parse(start_addr+ptrSize*56,ptrSize)
            ida_bytes.set_cmt(start_addr+ptrSize*56,'modulehashes',False)
            self.hashmain = common.get_qword(start_addr+ptrSize*59)
            ida_bytes.set_cmt(start_addr+ptrSize*59,'hasmain',False)
            self.gcdatamask = common.bitvector.parse(start_addr+ptrSize*60)
            ida_bytes.set_cmt(start_addr+ptrSize*60,'gcdatamask.n',False)
            ida_bytes.set_cmt(start_addr+ptrSize*61,'gcdatamask.bytedata',False)
            self.gcbssmask = common.bitvector.parse(start_addr+ptrSize*62)
            ida_bytes.set_cmt(start_addr+ptrSize*62,'gcbssmask.n',False)
            ida_bytes.set_cmt(start_addr+ptrSize*63,'gcbssmask.bytedata',False)
            self.typemap = common.get_qword(start_addr+ptrSize*64)
            ida_bytes.set_cmt(start_addr+ptrSize*64,'typemap',False)
            self.bad = common.get_qword(start_addr+ptrSize*65)
            ida_bytes.set_cmt(start_addr+ptrSize*65,'bad',False)
            self.next = common.get_qword(start_addr+ptrSize*66)
            ida_bytes.set_cmt(start_addr+ptrSize*66,'next',False)

    def parsed_typelink(self):
        self.rtypes = {}
        for addr in self.typelinks.parsed_types.keys():
            rtype = self.typelinks.parsed_types[addr]
            kind = rtype.get_kind()
            if kind not in self.rtypes.keys():
                self.rtypes[kind] = {}
            self.rtypes[kind][rtype.name_str] = rtype
        




        