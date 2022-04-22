#encoding:utf-8
import ida_bytes
import idaapi
idaapi.require('pcHeader')
idaapi.require('common')
idaapi.require('typelink')
idaapi.require('itablink')


class ModuleData():
    '''
go 1.18.1
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
	rodata                uintptr
	gofunc                uintptr // go.func.*

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
    '''
    def get_field_addrs(self,start_addr):
        self.start_addr = start_addr
        type_uint32 = 4
        type_uint8 = 1
        type_uint = type_int = type_uintptr = type_map = 8
        type_slice = 24
        type_string = type_bitvector = 16
        _pcHeader = start_addr
        funcnametab = _pcHeader + type_uintptr
        cutab = funcnametab + type_slice
        filetab = cutab + type_slice
        pctab = filetab + type_slice
        pclntable = pctab + type_slice
        ftab = pclntable + type_slice
        findfunctab = ftab + type_slice
        minpc = findfunctab + type_uintptr
        maxpc = minpc + type_uintptr
        text = maxpc + type_uintptr
        etext = text + type_uintptr
        noptrdata = etext + type_uintptr
        enoptrdata = noptrdata + type_uintptr
        data = enoptrdata + type_uintptr
        edata = data + type_uintptr
        bss = edata + type_uintptr
        ebss = bss + type_uintptr
        noptrbss = ebss + type_uintptr
        enoptrbss = noptrbss + type_uintptr
        end = enoptrbss + type_uintptr
        gcdata = end + type_uintptr
        gcbss = gcdata + type_uintptr
        types = gcbss + type_uintptr
        etypes = types + type_uintptr
        rodata =  etypes + type_uintptr
        gofunc = rodata + type_uintptr
        textsectmap = gofunc + type_uintptr
        typelinks = textsectmap + type_slice #typelink.TypeLinks
        itablinks = typelinks + type_slice #itablink.ItabLinks
        ptab = itablinks + type_slice
        pluginpath = ptab + type_slice
        pkghashes = pluginpath + type_string
        modulename = pkghashes + type_slice
        modulehashes = modulename + type_string
        hasmain = modulehashes + type_slice
        gcdatamask = hasmain + type_uint8 + 7 # 7 is pad len
        gcbssmask = gcdatamask + type_bitvector
        typemap = gcbssmask + type_bitvector
        bad = typemap + type_map
        next = bad + type_uint8 + 7 # 7 is pad len

        self.addrs = {}
        self.addrs['pcHeader_addr'] = {"addr":_pcHeader,"get":common.get_qword,"cmt":"pcHeader"}
        self.addrs['funcnametab'] = {"addr":funcnametab,"get":common.slice.parse,"cmt":"funcnametab"}
        self.addrs['cutab'] = {"addr":cutab,"get":common.slice.parse,"cmt":"cutab"}
        self.addrs['filetab'] = {"addr":filetab,"get":common.slice.parse,"cmt":"filetab"}
        self.addrs['pctab'] = {"addr":pctab,"get":common.slice.parse,"cmt":"pctab"}
        self.addrs['pclntable'] = {"addr":pclntable,"get":common.slice.parse,"cmt":"pclntable"}
        self.addrs['ftab'] = {"addr":ftab,"get":common.slice.parse,"cmt":"ftab"}
        self.addrs['findfunctab'] = {"addr":findfunctab,"get":common.get_qword,"cmt":"findfunctab"}
        self.addrs['minpc'] = {"addr":minpc,"get":common.get_qword,"cmt":"minpc"}
        self.addrs['maxpc'] = {"addr":maxpc,"get":common.get_qword,"cmt":"maxpc"}
        self.addrs['text'] = {"addr":text,"get":common.get_qword,"cmt":"text"}
        self.addrs['etext'] = {"addr":etext,"get":common.get_qword,"cmt":"etext"}
        self.addrs['noptrdata'] = {"addr":noptrdata,"get":common.get_qword,"cmt":"noptrdata"}
        self.addrs['enoptrdata'] = {"addr":enoptrdata,"get":common.get_qword,"cmt":"enoptrdata"}
        self.addrs['data'] = {"addr":data,"get":common.get_qword,"cmt":"data"}
        self.addrs['edata'] = {"addr":edata,"get":common.get_qword,"cmt":"edata"}
        self.addrs['bss'] = {"addr":bss,"get":common.get_qword,"cmt":"bss"}
        self.addrs['ebss'] = {"addr":ebss,"get":common.get_qword,"cmt":"ebss"}
        self.addrs['noptrbss'] = {"addr":noptrbss,"get":common.get_qword,"cmt":"noptrbss"}
        self.addrs['enoptrbss'] = {"addr":enoptrbss,"get":common.get_qword,"cmt":"enoptrbss"}
        self.addrs['end'] = {"addr":end,"get":common.get_qword,"cmt":"end"}
        self.addrs['gcdata'] = {"addr":gcdata,"get":common.get_qword,"cmt":"gcdata"}
        self.addrs['gcbss'] = {"addr":gcbss,"get":common.get_qword,"cmt":"gcbss"}
        self.addrs['types'] = {"addr":types,"get":common.get_qword,"cmt":"types"}
        self.addrs['etypes'] = {"addr":etypes,"get":common.get_qword,"cmt":"etypes"}
        self.addrs['rodata'] = {"addr":rodata,"get":common.get_qword,"cmt":"rodata"}
        self.addrs['gofunc'] = {"addr":gofunc,"get":common.get_qword,"cmt":"gofunc"}
        self.addrs['textsectmap'] = {"addr":textsectmap,"get":common.slice.parse,"cmt":"textsectmap"}
        self.addrs['typelinks'] = {"addr":typelinks,"cmt":"typelinks"}
        self.addrs['itablinks'] = {"addr":itablinks,"cmt":"itablinks"}
        self.addrs['ptab'] = {"addr":ptab,"get":common.slice.parse,"cmt":"ptab"}
        self.addrs['pluginpath'] = {"addr":pluginpath,"get":common.String.parse,"cmt":"pluginpath"}
        self.addrs['pkghashes'] = {"addr":pkghashes,"get":common.slice.parse,"cmt":"pkghashes"}
        self.addrs['modulename'] = {"addr":modulename,"get":common.String.parse,"cmt":"modulename"}
        self.addrs['modulehashes'] = {"addr":modulehashes,"get":common.slice.parse,"cmt":"modulehashes"}
        self.addrs['hasmain'] = {"addr":hasmain,"get":common.get_qword,"cmt":"hasmain"}
        self.addrs['gcdatamask'] = {"addr":gcdatamask,"get":common.bitvector.parse,"cmt":"gcdatamask"}
        self.addrs['gcbssmask'] = {"addr":gcbssmask,"get":common.bitvector.parse,"cmt":"gcbssmask"}
        self.addrs['typemap'] = {"addr":typemap,"get":common.get_qword,"cmt":"typemap"}
        self.addrs['bad'] = {"addr":bad,"get":common.get_qword,"cmt":"bad"}
        self.addrs['next'] = {"addr":next,"get":common.get_qword,"cmt":"next"}



    def __init__(self,start_addr,parse:bool=True):
        '''
        增加parse参数，主要是为了仅读取数据，而不解析，用于寻找firstmodule和pcheader时进行数据比较，
        而不影响数据类型
        '''
        self.get_field_addrs(start_addr)
        for name,dicts in self.addrs.items():
            if hasattr(self,name):
                print("class funcinifo already has"+name)
            else:
                attr_addr = dicts['addr']
                cmt = dicts['cmt']
                if "get" in dicts.keys():
                    get_func = dicts['get']
                    setattr(self,name,get_func(attr_addr,parse))
                if len(cmt) > 0  and parse:
                    ida_bytes.set_cmt(attr_addr,cmt,False)
        if parse:
            self.pcHeader = pcHeader.pcHeader(self.pcHeader_addr,self.start_addr)
            self.typelinks = typelink.TypeLinks(self.addrs['typelinks']['addr'],self)
            self.itablinks = itablink.ItabLinks(self.addrs['itablinks']['addr'],self)

       

    def parse_typelink(self):
        self.rtypes = {}
        for addr in self.typelinks.parsed_types.keys():
            rtype = self.typelinks.parsed_types[addr]
            kind = rtype.get_kind()
            if kind not in self.rtypes.keys():
                self.rtypes[kind] = {}
            self.rtypes[kind][rtype.name_str] = rtype
        




        