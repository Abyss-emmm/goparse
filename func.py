#encoding:utf-8
import ida_bytes
import idaapi
import idc
import ida_offset
idaapi.require('common')


class functab():
    '''
    go 1.16.8
    src\runtime\symtab.go
    type functab struct {
	    entry   uintptr
	    funcoff uintptr
    }
    '''

    def __init__(self,start_addr,pcheader):
        self.pcheader = pcheader
        self.start_addr = start_addr
        self.entry = common.get_qword(start_addr)
        self.funcoff = common.get_qword(start_addr+pcheader.ptrSize)
        ida_offset.op_plain_offset(start_addr+pcheader.ptrSize,0,self.pcheader.pclntab_addr)
        self.funcinfo = funcinfo(self.pcheader.pclntab_addr+self.funcoff,pcheader)
        # self.funcname = self.funcinfo.funcname
        # self.args = self.funcinfo.args


class funcinfo():
    '''
    go 1.16.8
    src\runtime\runtime2.go
    type _func struct {
	    entry   uintptr // start pc
	    nameoff int32   // function name
	    args        int32  // in/out args size
	    deferreturn uint32 // offset of start of a deferreturn call instruction from entry, if any.
	    pcsp      uint32
	    pcfile    uint32
	    pcln      uint32
	    npcdata   uint32
	    cuOffset  uint32  // runtime.cutab offset of this function's CU
	    funcID    funcID  // set for certain special runtime functions
	    _         [2]byte // pad
	    nfuncdata uint8   // must be last
    }
    '''
    def __init__(self,addr,pcheader):
        self.pcheader = pcheader
        ptrSize = pcheader.ptrSize
        offset_size = ptrSize//2
        self.entry = common.get_qword(addr)
        self.nameoff = common.get_dword(addr+ptrSize)
        self.args = common.get_dword(addr+ptrSize+offset_size)
        self.deferreturn = common.get_dword(addr+ptrSize+offset_size*2)
        self.pcsp = common.get_dword(addr+ptrSize+offset_size*3)
        self.pcfile = common.get_dword(addr+ptrSize+offset_size*4)
        self.pcln = common.get_dword(addr+ptrSize+offset_size*5)
        self.npcdata = common.get_dword(addr+ptrSize+offset_size*6)
        self.cuOffset = common.get_dword(addr+ptrSize+offset_size*7)
        self.funcID = common.get_byte(addr+ptrSize+offset_size*8)
        common.get_word(addr+ptrSize+offset_size*8+1)
        self.nfuncdata = common.get_byte(addr+ptrSize+offset_size*8+3)
        self.funcname = idc.get_strlit_contents(pcheader.funcname_addr+self.nameoff)

        if self.pcfile !=0:
            ida_offset.op_plain_offset(addr+ptrSize+offset_size*4,0,pcheader.pctab)
            fileno = common.read_pcvalue(pcheader.pctab+self.pcfile)
            if fileno == -1:
                self.filename = "?"
            else:
                fileoff_addr = pcheader.cutab+(self.cuOffset+fileno)*4
                fileoff = common.get_dword(fileoff_addr)
                ida_offset.op_plain_offset(fileoff_addr,0,pcheader.filetab)
                if fileoff != 0xffffffff:
                    self.filename = idc.get_strlit_contents(pcheader.filetab+fileoff).decode('utf-8')
                else:
                    self.filename = "?"
        else:
             self.filename = "?"

        if self.pcln != 0:
            ida_offset.op_plain_offset(addr+ptrSize+offset_size*5,0,pcheader.pctab)
            self.line = common.read_pcvalue(pcheader.pctab+self.pcln)
        else:
            self.line = -1


        ida_offset.op_plain_offset(addr+ptrSize,0,pcheader.funcname_addr)
        ida_bytes.set_cmt(addr+ptrSize,"Name:"+self.funcname.decode('utf-8'),False)
        ida_bytes.set_cmt(addr+ptrSize+offset_size,"args size:%d bytes" % self.args,False)
        if self.deferreturn != 0:
            ida_bytes.set_cmt(addr+ptrSize+offset_size*2,"defer return:"+hex(self.entry+self.deferreturn),False)
        else:
            ida_bytes.set_cmt(addr+ptrSize+offset_size*2,"defer return:null",False)
        ida_bytes.set_cmt(addr+ptrSize+offset_size*3,"pcsp",False)
        ida_bytes.set_cmt(addr+ptrSize+offset_size*4,"pcfile:"+self.filename,False)
        ida_bytes.set_cmt(addr+ptrSize+offset_size*5,"pcln:%d" % self.line,False)
        ida_bytes.set_cmt(addr+ptrSize+offset_size*6,"npcdata",False)
        ida_bytes.set_cmt(addr+ptrSize+offset_size*7,"cuOffset",False)
        ida_bytes.set_cmt(addr+ptrSize+offset_size*8,"funcID",False)
        ida_bytes.set_cmt(addr+ptrSize+offset_size*8+1,"pad",False)
        ida_bytes.set_cmt(addr+ptrSize+offset_size*8+3,"nfuncdata",False)
        pcdata_addr = addr+ptrSize+offset_size*8+4
        for i in range(0,self.npcdata):
            common.get_dword(pcdata_addr+i*4)
            ida_offset.op_plain_offset(pcdata_addr+i*4,0,pcheader.pctab)
            ida_bytes.set_cmt(pcdata_addr+i*4,"pcdata:%d" % i,False)
        funcdata_addr = pcdata_addr+self.npcdata*4
        if funcdata_addr & 4 != 0:
            common.get_dword(funcdata_addr)
            ida_bytes.set_cmt(funcdata_addr,"pad",False)
            funcdata_addr += 4
        for i in range(0,self.nfuncdata):
            common.get_qword(funcdata_addr+i*ptrSize)
            ida_bytes.set_cmt(funcdata_addr+i*ptrSize,"funcdata:%d" % i,False)
        

        


