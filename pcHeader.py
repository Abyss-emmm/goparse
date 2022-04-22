#encoding:utf-8

import idaapi
import ida_offset
import ida_bytes
idaapi.require('common')
idaapi.require('func')
idaapi.require('moduledata')
class pcHeader():
    '''
    go 1.18.1
    src\runtime\symtab.go
type pcHeader struct {
	magic          uint32  // 0xFFFFFFF0
	pad1, pad2     uint8   // 0,0
	minLC          uint8   // min instruction size
	ptrSize        uint8   // size of a ptr in bytes
	nfunc          int     // number of functions in the module
	nfiles         uint    // number of entries in the file tab
	textStart      uintptr // base for function entry PC offsets in this module, equal to moduledata.text
	funcnameOffset uintptr // offset to the funcnametab variable from pcHeader
	cuOffset       uintptr // offset to the cutab variable from pcHeader
	filetabOffset  uintptr // offset to the filetab variable from pcHeader
	pctabOffset    uintptr // offset to the pctab variable from pcHeader
	pclnOffset     uintptr // offset to the pclntab variable from pcHeader
}
    '''
    def get_field_addrs(self,start_addr):
        self.start_addr = start_addr
        type_uint32 = 4
        type_uint8 = 1
        type_uint = type_int = type_uintptr = 8
        magic = start_addr
        pad1 = magic + type_uint32
        pad2 = pad1 + type_uint8
        minLc = pad2 + type_uint8
        ptrSize = minLc + type_uint8
        nfunc = ptrSize + type_uint8
        nfiles = nfunc + type_int
        textStart = nfiles + type_uint
        funcnameOffset = textStart + type_uintptr
        cuOffset = funcnameOffset + type_uintptr
        filetabOffset = cuOffset + type_uintptr
        pctabOffset = filetabOffset + type_uintptr
        pclnOffset = pctabOffset + type_uintptr
        self.addrs = {}
        self.addrs['magic'] = {"addr":magic,"get":common.get_dword,"cmt":"magic"}
        self.addrs['pad1'] = {"addr":pad1,"get":common.get_byte,"cmt":"pad1"}
        self.addrs['pad2'] = {"addr":pad2,"get":common.get_byte,"cmt":"pad2"}
        self.addrs['minLc'] = {"addr":minLc,"get":common.get_byte,"cmt":"minLc"}
        self.addrs['ptrSize'] = {"addr":ptrSize,"get":common.get_byte,"cmt":"ptrSize"}
        self.addrs['nfunc'] = {"addr":nfunc,"get":common.get_qword,"cmt":"nfunc"}
        self.addrs['nfiles'] = {"addr":nfiles,"get":common.get_qword,"cmt":"nfiles"}
        self.addrs['textStart'] = {"addr":textStart,"get":common.get_qword,"cmt":"textStart"}
        self.addrs['funcnameOffset'] = {"addr":funcnameOffset,"get":common.get_qword,"cmt":"funcnameOffset"}
        self.addrs['cuOffset'] = {"addr":cuOffset,"get":common.get_qword,"cmt":"cuOffset"}
        self.addrs['filetabOffset'] = {"addr":filetabOffset,"get":common.get_qword,"cmt":"filetabOffset"}
        self.addrs['pctabOffset'] = {"addr":pctabOffset,"get":common.get_qword,"cmt":"pctabOffset"}
        self.addrs['pclnOffset'] = {"addr":pclnOffset,"get":common.get_qword,"cmt":"pclnOffset"}
        
    
    def __init__(self, start_addr,moduledata_addr,parse:bool=True):
        self.moduledata_addr = moduledata_addr
        self.get_field_addrs(start_addr)
        for name,dicts in self.addrs.items():
            if hasattr(self,name):
                print("class funcinifo already has"+name)
            else:
                attr_addr = dicts['addr']
                get_func = dicts['get']
                cmt = dicts['cmt']
                setattr(self,name,get_func(attr_addr,parse))
                if len(cmt) > 0 :
                    ida_bytes.set_cmt(attr_addr,cmt,False)
       
        self.funcname_addr = start_addr+self.funcnameOffset
        self.pclntab_addr = start_addr+self.pclnOffset
        self.pctab = self.pctabOffset + start_addr #虽然moduledata中也有，但是还未解析，所以此处需要单独计算一下
        self.cutab = self.cuOffset + start_addr #虽然moduledata中也有，但是还未解析，所以此处需要单独计算一下
        self.filetab = self.filetabOffset + start_addr
        if parse:
            #go 1.18与1.16的的pcHeader结构体不一样，在Offset类型的成员前多了一个textStart属性，因此解析offset属性的偏移+1*ptrSize
            ida_offset.op_plain_offset(self.addrs['funcnameOffset']['addr'],0,start_addr)
            ida_offset.op_plain_offset(self.addrs['cuOffset']['addr'],0,start_addr)
            ida_offset.op_plain_offset(self.addrs['filetabOffset']['addr'],0,start_addr)
            ida_offset.op_plain_offset(self.addrs['pctabOffset']['addr'],0,start_addr)
            ida_offset.op_plain_offset(self.addrs['pclnOffset']['addr'],0,start_addr)
            self.pclntab = []
            self.funcs = {}
            for i in range(0,self.nfunc):
                _func = func.functab(self.pclntab_addr+i*8,self) #一个funinfo占8字节，go 1.16.8的占16字节
                self.pclntab.append(_func)
                func_info = "funcname:%s\ninput args size:0x%x bytes\nfilename:%s\nfileno:%d" % (_func.funcinfo.funcname.decode('utf-8'),_func.funcinfo.args,_func.funcinfo.filename,_func.funcinfo.line)
                self.funcs[_func.funcinfo.entry] = func_info
    
    def is_valid(pcheader_addr,moduledata_addr):
        pcheader = pcHeader(pcheader_addr,moduledata_addr,False)
        firstmoduledata = moduledata.ModuleData(moduledata_addr,False)
        if firstmoduledata.funcnametab.addr == pcheader.funcname_addr and \
            firstmoduledata.cutab.addr == pcheader.cutab and \
            firstmoduledata.filetab.addr == pcheader.filetab and \
            firstmoduledata.pctab.addr == pcheader.pctab and \
            firstmoduledata.pclntable.addr == pcheader.pclntab_addr:
            return True
        return False





