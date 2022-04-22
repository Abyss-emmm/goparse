#encoding:utf-8

import idaapi
import ida_offset
idaapi.require('common')
idaapi.require('func')
idaapi.require('moduledata')
class pcHeader():
    '''
    go 1.16.8
    src\runtime\symtab.go
    type pcHeader struct {
0x0	    magic          uint32  // 0xFFFFFFFA
0x4	    pad1, pad2     uint8   // 0,0
0x6	    minLC          uint8   // min instruction size
0x7	    ptrSize        uint8   // size of a ptr in bytes
0x8	    nfunc          int     // number of functions in the module
0x10    nfiles         uint    // number of entries in the file tab.
0x18    funcnameOffset uintptr // offset to the funcnametab variable from pcHeader
0x20    cuOffset       uintptr // offset to the cutab variable from pcHeader
0x28    filetabOffset  uintptr // offset to the filetab variable from pcHeader
0x30    pctabOffset    uintptr // offset to the pctab varible from pcHeader
0x38    pclnOffset     uintptr // offset to the pclntab variable from pcHeader
    }
    '''
    
    def __init__(self, start_addr,moduledata_addr,parse:bool=True):
        self.moduledata_addr = moduledata_addr
        self.start_addr = start_addr
        self.minLC = common.get_byte(start_addr+0x6,parse)
        self.ptrSize = common.get_byte(start_addr+0x7,parse)
        self.nfunc = common.get_qword(start_addr+self.ptrSize,parse)
        self.nfiles = common.get_qword(start_addr+self.ptrSize*2,parse)
        self.funcnameOffset = common.get_qword(start_addr+self.ptrSize*3,parse)
        self.cuOffset = common.get_qword(start_addr+self.ptrSize*4,parse)
        self.filetabOffset = common.get_qword(start_addr+self.ptrSize*5,parse)
        self.pctabOffset = common.get_qword(start_addr+self.ptrSize*6,parse)
        self.pclnOffset = common.get_qword(start_addr+self.ptrSize*7,parse)
        self.funcname_addr = start_addr+self.funcnameOffset
        self.pclntab_addr = start_addr+self.pclnOffset
        self.pctab = self.pctabOffset + start_addr #虽然moduledata中也有，但是还未解析，所以此处需要单独计算一下
        self.cutab = self.cuOffset + start_addr #虽然moduledata中也有，但是还未解析，所以此处需要单独计算一下
        self.filetab = self.filetabOffset + start_addr
        if parse:
            ida_offset.op_plain_offset(start_addr+self.ptrSize*3,0,start_addr)
            ida_offset.op_plain_offset(start_addr+self.ptrSize*4,0,start_addr)
            ida_offset.op_plain_offset(start_addr+self.ptrSize*5,0,start_addr)
            ida_offset.op_plain_offset(start_addr+self.ptrSize*6,0,start_addr)
            ida_offset.op_plain_offset(start_addr+self.ptrSize*7,0,start_addr)
            self.pclntab = []
            self.funcs = {}
            for i in range(0,self.nfunc):
                _func = func.functab(self.pclntab_addr+i*2*self.ptrSize,self)
                self.pclntab.append(_func)
                func_info = "funcname:%s\ninput and output args size:0x%x bytes\nfilename:%s\nfileno:%d" % (_func.funcinfo.funcname.decode('utf-8'),_func.funcinfo.args,_func.funcinfo.filename,_func.funcinfo.line)
                self.funcs[_func.entry] = func_info
    
    def is_valid(pcheader_addr,moduledata_addr):
        pcheader = pcHeader(pcheader_addr,moduledata_addr,False)
        firstmoduledata = moduledata.ModuleData(moduledata_addr,False)
        if firstmoduledata.funcname.addr == pcheader.funcname_addr and \
            firstmoduledata.cutab.addr == pcheader.cutab and \
            firstmoduledata.filetab.addr == pcheader.filetab and \
            firstmoduledata.pctab.addr == pcheader.pctab and \
            firstmoduledata.pclntable.addr == pcheader.pclntab_addr:
            return True
        return False





