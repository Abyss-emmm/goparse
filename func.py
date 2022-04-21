#encoding:utf-8
import ida_bytes
import idaapi
import idc
import ida_offset
idaapi.require('common')


class functab():
    '''
    go 1.18.1
    src\runtime\symtab.go
type functab struct {
	entryoff uint32 // relative to runtime.text
	funcoff  uint32
}
    '''

    def __init__(self,start_addr,pcheader):
        self.pcheader = pcheader
        self.start_addr = start_addr
        self.entryoff = common.get_dword(start_addr)
        self.funcoff = common.get_dword(start_addr+4)
        ida_offset.op_plain_offset(start_addr,0,self.pcheader.textStart)
        ida_offset.op_plain_offset(start_addr+4,0,self.pcheader.pclntab_addr)
        self.funcinfo = funcinfo(self.pcheader.pclntab_addr+self.funcoff,pcheader)
        # self.funcname = self.funcinfo.funcname
        # self.args = self.funcinfo.args


class funcinfo():
    '''
    go 1.18.1
    src\runtime\runtime2.go
type _func struct {
	entryoff uint32 // start pc, as offset from moduledata.text/pcHeader.textStart
	nameoff  int32  // function name

	args        int32  // in/out args size
	deferreturn uint32 // offset of start of a deferreturn call instruction from entry, if any.

	pcsp      uint32
	pcfile    uint32
	pcln      uint32
	npcdata   uint32
	cuOffset  uint32 // runtime.cutab offset of this function's CU
	funcID    funcID // set for certain special runtime functions
	flag      funcFlag
	_         [1]byte // pad
	nfuncdata uint8   // must be last, must end on a uint32-aligned boundary
}
    '''
    def get_field_addrs(self,start_addr):
        offset_size = (self.pcheader.ptrSize)//2
        entryoff = start_addr
        nameoff = entryoff + offset_size
        args = nameoff + offset_size
        deferreturn = args + offset_size
        pcsp = deferreturn + offset_size
        pcfile = pcsp + offset_size
        pcln = pcfile + offset_size
        npcdata = pcln + offset_size
        cuOffset = npcdata + offset_size
        funcID = cuOffset + offset_size
        flag = funcID + 1
        pad = flag + 1
        nfuncdata = pad + 1
        self.addrs = {}
        self.addrs['entryoff'] = {"addr":entryoff,"get":common.get_dword,"cmt":"entryoff"}
        self.addrs['nameoff'] = {"addr":nameoff,"get":common.get_dword,"cmt":""}
        self.addrs['args'] = {"addr":args,"get":common.get_dword,"cmt":""}
        self.addrs['deferreturn'] = {"addr":deferreturn,"get":common.get_dword,"cmt":"deferreturn"}
        self.addrs['pcsp'] = {"addr":pcsp,"get":common.get_dword,"cmt":"pcsp"}
        self.addrs['pcfile'] = {"addr":pcfile,"get":common.get_dword,"cmt":"pcfile"}
        self.addrs['pcln'] = {"addr":pcln,"get":common.get_dword,"cmt":"pcln"}
        self.addrs['npcdata'] = {"addr":npcdata,"get":common.get_dword,"cmt":"npcdata"}
        self.addrs['cuOffset'] = {"addr":cuOffset,"get":common.get_dword,"cmt":"cuOffset"}
        self.addrs['funcID'] = {"addr":funcID,"get":common.get_byte,"cmt":"funcID"}
        self.addrs['flag'] = {"addr":flag,"get":common.get_byte,"cmt":"flag"}
        self.addrs['pad'] = {"addr":pad,"get":common.get_byte,"cmt":"pad"}
        self.addrs['nfuncdata'] = {"addr":nfuncdata,"get":common.get_byte,"cmt":"nfuncdata"}

    def __init__(self,start_addr,pcheader):
        self.pcheader = pcheader
        self.get_field_addrs(start_addr)
        for name,dicts in self.addrs.items():
            if hasattr(self,name):
                print("class funcinifo already has"+name)
            else:
                attr_addr = dicts['addr']
                get_func = dicts['get']
                cmt = dicts['cmt']
                setattr(self,name,get_func(attr_addr))
                if len(cmt) > 0 :
                    ida_bytes.set_cmt(attr_addr,cmt,False)

        ida_offset.op_plain_offset(self.addrs['entryoff']['addr'],0,self.pcheader.textStart)
        self.entry = self.entryoff + self.pcheader.textStart

        self.funcname = idc.get_strlit_contents(self.pcheader.funcname_addr+self.nameoff)
        ida_offset.op_plain_offset(self.addrs['nameoff']['addr'],0,self.pcheader.funcname_addr)
        ida_bytes.set_cmt(self.addrs['nameoff']['addr'],"Name:"+self.funcname.decode('utf-8'),False)

        ida_bytes.set_cmt(self.addrs['args']['addr'],"args size:%d bytes" % self.args,False)

        if self.deferreturn != 0:
            ida_bytes.set_cmt(self.addrs['deferreturn']['addr'],"defer return:"+hex(self.entry+self.deferreturn),False)
        else:
            ida_bytes.set_cmt(self.addrs['deferreturn']['addr'],"defer return:null",False)

        if self.pcfile !=0:
            ida_offset.op_plain_offset(self.addrs['pcfile']['addr'],0,pcheader.pctab)
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
        ida_bytes.set_cmt(self.addrs['pcfile']['addr'],"pcfile:"+self.filename,False)

        if self.pcln != 0:
            ida_offset.op_plain_offset(self.addrs['pcln']['addr'],0,pcheader.pctab)
            self.line = common.read_pcvalue(pcheader.pctab+self.pcln)
        else:
            self.line = -1
        ida_bytes.set_cmt(self.addrs['pcln']['addr'],"pcln:%d" % self.line,False)

        #pcdata is data after _func
        pcdata_addr = self.addrs['nfuncdata']['addr'] + 1
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
            common.get_qword(funcdata_addr+i*8)
            ida_bytes.set_cmt(funcdata_addr+i*8,"funcdata:%d" % i,False)
        
        
        

        


