#encoding:utf-8

import idaapi
import ida_bytes
import ida_name
import ida_offset
import ida_struct
import traceback
idaapi.require('common')
idaapi.require('moduledata')

class TypeLinks():
    def __init__(self,start_addr,moduledata):
        self.start_addr = start_addr
        self.moduledata = moduledata
        self.typelinks_slice = common.slice.parse(start_addr,moduledata.pcHeader.ptrSize)
        self.parsed_types = {}

        base_addr = moduledata.types
        typeoff_size = 4
        for i in range(0,self.typelinks_slice.len):
            ida_bytes.create_dword(self.typelinks_slice.addr+i*typeoff_size,4,False)
            ida_offset.op_plain_offset(self.typelinks_slice.addr+i*typeoff_size,0,base_addr)
            type_addr = ida_bytes.get_dword(self.typelinks_slice.addr+i*typeoff_size)+base_addr
            self.parse_type(type_addr)
        
    def has_parsed(self,addr):
        if addr is None:
            return True
        return (addr in self.parsed_types.keys())
    
    def parse_type(self,type_addr):
        rtype = RType(type_addr,self)
        self.parsed_types[type_addr] = rtype
        if rtype.get_kind() == "Ptr":
            ptrtype = PtrType(rtype)
            self.parsed_types[type_addr] = ptrtype
            if not self.has_parsed(ptrtype.elem):
                self.parse_type(ptrtype.elem)
        elif rtype.get_kind() == "Struct":
            structtype = StructType(rtype)
            self.parsed_types[type_addr] = structtype
        elif rtype.get_kind() == "Interface":
            interfacetype = InterfaceType(rtype)
            self.parsed_types[type_addr] = interfacetype
            for i in range(0,len(interfacetype.methods)):
                if not self.has_parsed(interfacetype.methods[i].typeaddr):
                    self.parse_type(interfacetype.methods[i].typeaddr)
        elif rtype.get_kind() == "Slice":
            slicetype = SliceType(rtype)
            self.parsed_types[type_addr] = slicetype
            if not self.has_parsed(slicetype.elem):
                self.parse_type(slicetype.elem)
        elif rtype.get_kind() == "Array":
            arraytype = ArrayType(rtype)
            self.parsed_types[type_addr] = arraytype
            if not self.has_parsed(arraytype.elem):
                self.parse_type(arraytype.elem)
            if not self.has_parsed(arraytype.slice):
                self.parse_type(arraytype.slice)
        elif rtype.get_kind() == "Func":
            functype = FuncType(rtype)
            self.parsed_types[type_addr] = functype
        elif rtype.get_kind() == "Map":
            maptype = MapType(rtype)
            self.parsed_types[type_addr] = maptype
            if not self.has_parsed(maptype.key):
                self.parse_type(maptype.key)
            if not self.has_parsed(maptype.elem):
                self.parse_type(maptype.elem)
            if not self.has_parsed(maptype.bucket):
                self.parse_type(maptype.bucket)
        elif rtype.get_kind() == "Chan":
            chantype = ChanType(rtype)
            self.parsed_types[type_addr] = chantype
        elif rtype.uncommon:
            rtype.parse_uncommon()
        if rtype.uncommon_type is not None:
            uncommon_type = rtype.uncommon_type
            for i in range(0,uncommon_type.mcount):
                if not self.has_parsed(uncommon_type.methods[i].typeaddr):
                    self.parse_type(uncommon_type.methods[i].typeaddr)





class RType():
    '''
    go1.16.8
    A single RType struct
    Refer: src/reflect/type.go
    type rtype struct {
        size       uintptr
        ptrdata    uintptr  // number of bytes in the type that can contain pointers
        hash       uint32   // hash of type; avoids computation in hash tables
        tflag      tflag    // extra type information flags
        align      uint8    // alignment of variable with this type
        fieldAlign uint8    // alignment of struct field with this type
        kind       uint8    // enumeration for C
        // function for comparing objects of this type
	    // (ptr to object A, ptr to object B) -> ==?
	    equal     func(unsafe.Pointer, unsafe.Pointer) bool
        gcdata     *byte    // garbage collection data
        str        nameOff  // string form
        ptrToThis  typeOff  // type for pointer to this type, may be zero
    }
    '''
    #Refer: src/reflect/type.go#kind
    
    def __init__(self,type_addr,typelink:TypeLinks):
        self.start_addr = type_addr
        self.typelink = typelink
        self.uncommon_type = None
        ptrSize = typelink.moduledata.pcHeader.ptrSize
        self.size = ida_bytes.get_qword(type_addr)
        self.tflag = ida_bytes.get_byte(type_addr+ptrSize*2+4)
        self.kind = ida_bytes.get_byte(type_addr+ptrSize*2+7)
        self.str = ida_bytes.get_dword(type_addr+ptrSize*5)
        self.ptrToThis = ida_bytes.get_dword(type_addr+ptrSize*5+4)
        self.parse_tflag()
        ida_bytes.create_qword(type_addr,ptrSize,False)
        ida_bytes.set_cmt(type_addr,"type size",False)
        ida_bytes.create_qword(type_addr+ptrSize,ptrSize,False)
        ida_bytes.set_cmt(type_addr+ptrSize,"type ptrdata",False)
        ida_bytes.create_dword(type_addr+ptrSize*2,ptrSize//2,False)
        ida_bytes.set_cmt(type_addr+ptrSize*2,"type hash",False)
        ida_bytes.create_byte(type_addr+ptrSize*2+4,1,False)
        ida_bytes.set_cmt(type_addr+ptrSize*2+4,self.tflag_comm,False)
        ida_bytes.create_byte(type_addr+ptrSize*2+5,1,False)
        ida_bytes.set_cmt(type_addr+ptrSize*2+5,"align",False)
        ida_bytes.create_byte(type_addr+ptrSize*2+6,1,False)
        ida_bytes.set_cmt(type_addr+ptrSize*2+6,"field align",False)
        ida_bytes.create_byte(type_addr+ptrSize*2+7,1,False)
        ida_bytes.set_cmt(type_addr+ptrSize*2+7,"Kind:"+self.get_kind(),False)
        ida_bytes.create_qword(type_addr+ptrSize*3,ptrSize,False)
        ida_bytes.set_cmt(type_addr+ptrSize*3,"type equal func",False)
        ida_bytes.create_qword(type_addr+ptrSize*4,ptrSize,False)
        ida_bytes.set_cmt(type_addr+ptrSize*4,"gcdata",False)
        ida_bytes.create_dword(type_addr+ptrSize*5,ptrSize//2,False)
        nameOff =self.str
        ida_offset.op_plain_offset(type_addr+ptrSize*5,0,self.typelink.moduledata.types)
        name_addr = self.typelink.moduledata.types + nameOff
        self.name = Name(name_addr,self)
        name_str = self.name.get_name()
        # 对于Star Prefix的将*替换为#，区分指针
        if "Star Prefix" in self.tflag_comm and name_str[0] == '*':
            name_str = '#' + name_str[1:]
        self.name_str = name_str
        ida_bytes.set_cmt(type_addr,name_str,True)#设置可重复注释，及引用时显示
        # 下面的先注释，改的太多，名字也太长了
        # ida_name.set_name(type_addr,"typelink_"+self.name.get_name().replace('*','_').replace(' ','_').replace(',','_').replace('{','_').replace('}','_').replace('[','_').replace(']','_').replace(';','_'))
        ida_bytes.set_cmt(type_addr+ptrSize*5,"Name:"+name_str,False)
        ida_bytes.create_dword(type_addr+ptrSize*5+4,ptrSize//2,False)
        ida_bytes.set_cmt(type_addr+ptrSize*5+4,"ptrToThis",False)
        if self.ptrToThis != 0 :
            ida_offset.op_plain_offset(type_addr+ptrSize*5+4,0,self.typelink.moduledata.types)
        self.self_size = 0x30

        
    def init(self,rtype):
        self.start_addr = rtype.start_addr
        self.typelink = rtype.typelink
        self.size = rtype.size
        self.tflag = rtype.tflag
        self.kind = rtype.kind
        self.str = rtype.str
        self.ptrToThis = rtype.ptrToThis
        self.name  = rtype.name
        self.self_size = rtype.self_size
        self.tflag_comm = rtype.tflag_comm
        self.uncommon = rtype.uncommon
        self.name_str = rtype.name_str

    def parse_tflag(self):
        # src/reflect/type.go#tflag
        tflagUncommon        = 0x1
        tflagExtraStar    = 0x2
        tflagNamed         = 0x4
        tflagRegularMemory = 0x8
        self.tflag_comm = 'tflag:'
        if self.tflag & tflagUncommon != 0:
            self.uncommon = True
            self.tflag_comm += "Uncommon;"
        else:
            self.uncommon = False
            self.tflag_comm += "Common;"
        if self.tflag & tflagExtraStar !=0:
            self.tflag_comm += "Star Prefix;"
        if self.tflag & tflagNamed !=0:
            self.tflag_comm += "Named"
        if self.tflag & tflagRegularMemory !=0:
            self.tflag_comm += "equal and hash func can treat"

    def get_kind(self):
        # src/reflect/type.go#kindMask
        TYPE_KINDS = ['Invalid Kind','Bool','Int','Int8','Int16','Int32','Int64','Uint','Uint8','Uint16','Uint32','Uint64','Uintptr','Float32','Float64','Complex64','Complex128','Array','Chan','Func','Interface','Map','Ptr','Slice','String','Struct','UnsafePointer']
        kindMask = (1 << 5) - 1
        return TYPE_KINDS[self.kind & kindMask]

    def parse_uncommon(self):
        if self.uncommon:
            self.uncommon_type = UncommonType(self.start_addr+self.self_size,self)
            self.self_size += 0x10


class Name():
    '''
    A rtype name struct
    Refer: https://golang.org/src/reflect/type.go

    name is an encoded type name with optional extra data.
    
    The first byte is a bit field containing:
    
        1<<0 the name is exported
        1<<1 tag data follows the name
        1<<2 pkgPath nameOff follows the name and tag
    
    The next two bytes are the data length:
    
         l := uint16(data[1])<<8 | uint16(data[2])
    
    Bytes [3:3+l] are the string data.
    
    If tag data follows then bytes 3+l and 3+l+1 are the tag length,
    with the data following.
    
    If the import path follows, then 4 bytes at the end of
    the data form a nameOff. The import path is only set for concrete
    methods that are defined in a different package than their type.
    
    If a name starts with "*", then the exported bit represents
    whether the pointed to type is exported.
    
    type name struct {
        bytes *byte
    }
    '''
    def __init__(self,name_addr,rtype:RType):
        self.start_addr = name_addr
        self.rtype = rtype
        self.flag = ida_bytes.get_byte(name_addr)
        self.len = (ida_bytes.get_byte(name_addr+1)<<8)|ida_bytes.get_byte(name_addr+2)
        self.name = ida_bytes.get_bytes(name_addr+3,self.len)
        self.is_exported = False
        self.has_tag = False
        self.has_pkgpath = False
        self.parse_flag()
        ida_bytes.create_byte(name_addr,1,False)
        ida_bytes.set_cmt(name_addr,self.flag_comm,False)
        ida_bytes.create_word(name_addr+1,2,False)
        ida_bytes.set_cmt(name_addr+1,"len:0x%x" % self.len,False)

    def parse_flag(self):
        EXPORTED = 0x1
        HAS_TAG = 0x2
        HAS_PKGPATH = 0x4
        self.flag_comm = "flag:"
        if self.flag & EXPORTED:
            self.is_exported = True
            self.flag_comm += "exported;"
        if self.has_tag & HAS_TAG:
            self.has_tag = True
            self.flag_comm += "has tag;"
        if self.flag & HAS_PKGPATH:
            self.has_pkgpath = True
            self.flag_comm += "has pkgpath"

    def get_name(self):
        name = ""
        if self.len > 0:
            try:
                name = self.name.decode('utf-8')
            except Exception as err:
                print(hex(self.rtype.start_addr),hex(self.start_addr))
                traceback.print_stack()
        return name


class PtrType(RType):
    '''
    go 1.16.8
    Refer: https://golang.org/src/reflect/type.go
    type ptrType struct {
    	rtype
    	elem *rtype // pointer element (pointed at) type
    }
    '''
    def __init__(self,rtype:RType):
        self.init(rtype)
        self.rtype = rtype
        ptrSize = self.typelink.moduledata.pcHeader.ptrSize
        self.elem = ida_bytes.get_qword(self.start_addr+self.self_size)
        self.self_size += ptrSize
        if self.uncommon:
            self.parse_uncommon()


class StructType(RType):
    '''
    go 1.16.8
    Refer: https://golang.org/src/reflect/type.go
    type structType struct {
    	rtype
    	pkgPath name
    	fields  []structField // sorted by offset
    }
    '''
    def __init__(self, rtype:RType):
        self.init(rtype)
        self.rtype = rtype
        ptrSize = self.typelink.moduledata.pcHeader.ptrSize
        self.pkgPath_addr = ida_bytes.get_qword(self.start_addr+self.self_size)
        if self.pkgPath_addr != 0:
            self.pkgPath = Name(self.pkgPath_addr,self)
            ida_bytes.set_cmt(self.start_addr+self.self_size,"pkgPath:"+self.pkgPath.get_name(),False)
        ida_bytes.create_qword(self.start_addr+self.self_size,ptrSize,False)
        self.fields_slice = common.slice.parse(self.start_addr+self.self_size+ptrSize,ptrSize)
        self.fields = []
        for i in range(0,self.fields_slice.len):
            field = Struct_Field(self.fields_slice.addr+i*0x18,self)
            self.fields.append(field)
        self.self_size += 0x20
        if self.uncommon:
            self.parse_uncommon()

    def show_struct(self):
        struct_info = "type %s struct{" % self.name_str
        for field in self.fields:
            field_info = "\n\t%s %s offset 0x%x" % (field.field_name.get_name(),field.type.name_str,field.offset)
            struct_info += field_info
        struct_info += "\n}"
        print(struct_info)
    
    def generate_struct(self):
        field_infos = []
        for field in self.fields:
            name = field.field_name.get_name()
            name = name.replace('#','').replace('.','_').replace('*',"_ptr_")
            offset = field.offset
            nbytes = field.type.size
            if field.type.name_str == '#string':
                field_info_addr = {"name":name+"_addr","offset":offset,"nbytes":8}
                field_info_len = {"name":name+"_len","offset":offset+8,"nbytes":8}
                field_infos.append(field_info_addr)
                field_infos.append(field_info_len)
            else:
                field_info = {"name":name,"offset":offset,"nbytes":nbytes}
                field_infos.append(field_info)
        fields_num = len(field_infos)
        struct_name = self.name_str.replace('#','').replace('.','_').replace('*',"_ptr_")
        idx = ida_struct.add_struc(idaapi.BADADDR,struct_name,False)
        struc = ida_struct.get_struc(idx)
        for i in range(fields_num):
            if i < fields_num-1:
                if field_infos[i]['nbytes'] != field_infos[i+1]['offset']-field_infos[i]['offset']:
                    print("%s type size(0x%x) is not equal its size(0x%x) in struct,offset is 0x%x" % (field_infos[i]['name'],field_infos[i]['nbytes'],field_infos[i+1]['offset']-field_infos[i]['offset'],field_infos[i]['offset']))
                    field_infos[i]['nbytes'] = field_infos[i+1]['offset']-field_infos[i]['offset']
            ida_struct.add_struc_member(struc,field_infos[i]['name'],field_infos[i]['offset'],ida_bytes.FF_DATA,None,field_infos[i]['nbytes'])
        



class Struct_Field():
    '''
    go 1.16.8
    Refer: https://golang.org/src/reflect/type.go
    type structField struct {
    	name        name    // name is always non-empty
    	typ         *rtype  // type of field
    	offsetEmbed uintptr // byte offset of field<<1 | isEmbedded
    }
    '''
    def __init__(self,field_addr,struct_type:StructType):
        ptrSize = struct_type.typelink.moduledata.pcHeader.ptrSize
        self.struct_type = struct_type
        field_name_addr = ida_bytes.get_qword(field_addr)
        field_type_addr = ida_bytes.get_qword(field_addr+ptrSize)
        self.offsetEmbed = ida_bytes.get_qword(field_addr+ptrSize*2)
        self.field_name = Name(field_name_addr,self)
        if not struct_type.typelink.has_parsed(field_type_addr):
            struct_type.typelink.parse_type(field_type_addr)
        self.type = struct_type.typelink.parsed_types[field_type_addr]
        self.offset = self.offsetEmbed >> 1
        self.is_embeded = (self.offsetEmbed&1 != 0)
        for i in range(0,3):
            ida_bytes.create_qword(field_addr+i*ptrSize,ptrSize,False)
        ida_bytes.set_cmt(field_addr,self.field_name.get_name(),False)
        offsetembed_cmt = "offset %d" % self.offset
        if self.is_embeded:
            offsetembed_cmt += ";is embeded"
        ida_bytes.set_cmt(field_addr+ptrSize*2,offsetembed_cmt,False)

class SliceType(RType):
    '''
    go 1.16.8
    Slice type
    Refer: https://golang.org/src/reflect/type.go

    type sliceType struct {
        rtype
        elem *rtype // slice element type
    }
    '''
    def __init__(self,rtype:RType):
        self.init(rtype)
        self.rtype = rtype
        self.elem = common.get_qword(self.start_addr+self.self_size)
        self.self_size += 0x8
        if self.uncommon:
            self.parse_uncommon()

class ArrayType(RType):
    '''
    go 1.16.8
    Array type  
    Refer: https://golang.org/src/reflect/type.go

    type arrayType struct {
        rtype
        elem  *rtype // array element type
        slice *rtype // slice type
        len   uintptr
    }
    '''
    def __init__(self,rtype:RType):
        self.init(rtype)
        self.rtype = rtype
        ptrSize = self.typelink.moduledata.pcHeader.ptrSize
        self.elem = common.get_qword(self.start_addr+self.self_size)
        self.slice = common.get_qword(self.start_addr+self.self_size+ptrSize)
        self.len = common.get_qword(self.start_addr+self.self_size+2*ptrSize)
        ida_bytes.set_cmt(self.start_addr+self.self_size+2*ptrSize,"Array len:%d"  % self.len,False)
        self.self_size += 0x18
        if self.uncommon:
            self.parse_uncommon()

class FuncType(RType):
    '''
    go 1.16.8
    Function Type
    Refer: https://golang.org/src/reflect/type.go

    type funcType struct {
        rtype
        inCount  uint16
        outCount uint16 // top bit is set if last input parameter is ...
    }

    funcType represents a function type.
    A *rtype for each in and out parameter is stored in an array that
    directly follows the funcType (and possibly its uncommonType). So
    a function type with one method, one input, and one output is:

    	struct {
    		funcType
    		uncommonType
    		[2]*rtype    // [0] is in, [1] is out
    	}
    '''
    def __init__(self,rtype:RType):
        self.init(rtype)
        self.rtype = rtype
        self.is_variadic = False
        self.is_pad = False
        self.inCount = common.get_word(self.start_addr+self.self_size)
        self.outCount = common.get_word(self.start_addr+self.self_size+2)
        VARIADIC_FLAG = 0x8000
        if self.outCount & VARIADIC_FLAG:
            self.is_variadic = True
            self.outCount =  self.outCount & 0x7fff
        ida_bytes.set_cmt(self.start_addr+self.self_size,"input parameter number:%d" % self.inCount,False)
        ida_bytes.set_cmt(self.start_addr+self.self_size+2,"output parameter number:%d" % self.outCount,False)
        self.self_size += 4
        if self.uncommon:
            # uncommon的情况，需要判断func type与uncommontype中间有4字节的padding数据
            if ida_bytes.get_dword(self.start_addr+self.self_size) == 0:
                self.is_pad = True
                self.self_size += 4
            self.parse_uncommon()



class InterfaceType(RType):
    '''
    Interface type   
    Refer: https://golang.org/src/reflect/type.go

    type interfaceType struct {
        rtype
        pkgPath name      // import path
        methods []imethod // sorted by hash
    }
    '''
    def __init__(self,rtype:RType):
        self.init(rtype)
        self.rtype = rtype
        ptrSize = self.typelink.moduledata.pcHeader.ptrSize
        self.pkgPath_addr = ida_bytes.get_qword(self.start_addr+self.self_size)
        if self.pkgPath_addr != 0:
            self.pkgPath = Name(self.pkgPath_addr,self)
            ida_bytes.set_cmt(self.start_addr+self.self_size,"pkgPath:"+self.pkgPath.get_name(),False)
        ida_bytes.create_qword(self.start_addr+self.self_size,ptrSize,False)
        ida_bytes.set_cmt(self.start_addr+self.self_size+ptrSize,"[]imethod",False)
        self.method_slice = common.slice.parse(self.start_addr+self.self_size+ptrSize,ptrSize)
        self.methods = []
        for i in range(0,self.method_slice.len):
            method_addr = self.method_slice.addr+i*ptrSize
            self.methods.append(Imethod(method_addr,self))
        self.self_size += 0x20
        if self.uncommon:
            self.parse_uncommon()

class Imethod():
    '''
    IMethod type    
    Refer: https://golang.org/src/reflect/type.go

    type imethod struct {
        name nameOff // name of method
        typ  typeOff // .(*FuncType) underneath
    }
    '''
    def __init__(self,start_addr,interfacetype:InterfaceType):
        self.start_addr = start_addr
        self.interfacetype = interfacetype
        nameoff = common.get_dword(start_addr)
        nameaddr = interfacetype.typelink.moduledata.types+nameoff
        self.name = Name(nameaddr,interfacetype)
        typeoff = common.get_dword(start_addr+4)
        self.typeaddr = interfacetype.typelink.moduledata.types+typeoff
        ida_bytes.set_cmt(start_addr,"Name:"+self.name.get_name(),True)
        ida_offset.op_plain_offset(start_addr+4,0,interfacetype.typelink.moduledata.types)

class MapType(RType):
    '''
    Map type
    Refer: https://golang.org/src/reflect/type.go

    type mapType struct {
        rtype
        key    *rtype // map key type
        elem   *rtype // map element (value) type
        bucket *rtype // internal bucket structure
        // function for hashing keys (ptr to key, seed) -> hash
        hasher     func(unsafe.Pointer, uintptr) uintptr // go version <1.14 has no this field
        keysize    uint8  // size of key slot
        valuesize  uint8  // size of value slot
        bucketsize uint16 // size of bucket
        flags      uint32
    }
    '''
    def __init__(self,rtype:RType):
        self.init(rtype)
        self.rtype = rtype
        ptrSize = rtype.typelink.moduledata.pcHeader.ptrSize
        self.key = common.get_qword(self.start_addr+self.self_size)
        self.elem = common.get_qword(self.start_addr+self.self_size+ptrSize)
        self.bucket = common.get_qword(self.start_addr+self.self_size+ptrSize*2)
        self.hasher = common.get_qword(self.start_addr+self.self_size+ptrSize*3)
        self.keysize = common.get_byte(self.start_addr+self.self_size+ptrSize*4)
        self.valuesize = common.get_byte(self.start_addr+self.self_size+ptrSize*4+1)
        self.bucketsize = common.get_word(self.start_addr+self.self_size+ptrSize*4+2)
        self.flags = common.get_dword(self.start_addr+self.self_size+ptrSize*4+4)
        ida_bytes.set_cmt(self.start_addr+self.self_size+ptrSize*3,"hasher",False)
        ida_bytes.set_cmt(self.start_addr+self.self_size+ptrSize*4,"keysize:%d" % self.keysize,False)
        ida_bytes.set_cmt(self.start_addr+self.self_size+ptrSize*4+1,"valuesize:%d" % self.valuesize,False)
        ida_bytes.set_cmt(self.start_addr+self.self_size+ptrSize*4+2,"bucketsize:%d" % self.bucketsize,False)
        self.self_size += 0x28
        if self.uncommon:
            self.parse_uncommon()
        
class ChanType(RType):
    '''
    go 1.16.8
    Channel type    
    Refer: https://golang.org/src/reflect/type.go

    type chanType struct {
        rtype
        elem *rtype  // channel element type
        dir  uintptr // channel direction (ChanDir)
    }
    type chanDir int

    const (
    	recvDir chanDir             = 1 << iota // <-chan
    	sendDir                                 // chan<-
    	bothDir = recvDir | sendDir             // chan
    )
    '''
    def __init__(self,rtype:RType):
        self.init(rtype)
        self.rtype = rtype
        ptrSize = rtype.typelink.moduledata.pcHeader.ptrSize
        self.elem = common.get_qword(self.start_addr+self.self_size)
        self.dir = common.get_qword(self.start_addr+self.self_size+ptrSize)
        ida_bytes.set_cmt(self.start_addr+self.self_size+ptrSize,self.get_direction(),False)
        self.self_size += 0x10
        if self.uncommon:
            self.parse_uncommon()

    def get_direction(self):
        recvDir = 0x1
        sendDir = 0x2
        self.directions = []
        if self.dir & recvDir:
            self.directions.append('recv')
        if self.dir & sendDir:
            self.directions.append('send')
        return "channel direction:" + "&".join(self.directions)

        

class UncommonType():
    '''
    go 1.16.8
    Uncommon type
    Refer: https://golang.org/src/reflect/type.go

    Wrapper around primaryType to access uncommon type:

    // uncommonType is present only for defined types or types with methods
    // (if T is a defined type, the uncommonTypes for T and *T have methods).
    // Using a pointer to this struct reduces the overall size required
    // to describe a non-defined type with no methods
    type uncommonType struct {
        pkgPath nameOff // import path; empty for built-in types like int, string
        mcount  uint16  // number of methods
        xcount  uint16  // number of exported methods
        moff    uint32  // offset from this uncommontype to [mcount]method
        _       uint32  // unused
    }
    '''
    def __init__(self,start_addr,rtype:RType):
        self.start_addr = start_addr
        self.rtype = rtype
        # ptrSize = rtype.typelink.moduledata.pcHeader.ptrSize
        pkgPath_off = common.get_dword(start_addr)
        self.pkgPath_addr = rtype.typelink.moduledata.types+pkgPath_off
        ida_offset.op_plain_offset(start_addr,0,rtype.typelink.moduledata.types)
        if self.pkgPath_addr != 0:
            self.pkgPath = Name(self.pkgPath_addr,rtype)
            ida_bytes.set_cmt(start_addr,"pkgPath:"+self.pkgPath.get_name(),False)
        self.mcount = common.get_word(start_addr+4)
        self.xcount = common.get_word(start_addr+6)
        ida_bytes.set_cmt(start_addr+4,"number of methods:%d" % self.mcount,False)
        ida_bytes.set_cmt(start_addr+6,"number of exported methods:%d" % self.xcount,False)
        self.moff = common.get_dword(start_addr+8)
        ida_offset.op_plain_offset(start_addr+8,0,start_addr)
        common.get_dword(start_addr+12)
        method_base_addr = start_addr+self.moff
        self.methods = []
        for i in range(0,self.mcount):
            method_addr = method_base_addr+i*0x10
            uncommmon_method = Uncommon_Method(method_addr,self)
            self.methods.append(uncommmon_method)

class Uncommon_Method():
    '''
    go 1.16.8
    Method type of no-interface type
    Refer: https://golang.org/src/reflect/type.go

    type method struct {
        name nameOff // name of method
        mtyp typeOff // method type (without receiver) // offset to an *rtype
        ifn  textOff // fn used in interface call (one-word receiver) // offset from top of text section
        tfn  textOff // fn used for normal method call // offset from top of text section
    }    
    '''
    def __init__(self,start_addr,uncommontype:UncommonType):
        self.start_addr = start_addr
        self.uncommontype = uncommontype
        text_addr = uncommontype.rtype.typelink.moduledata.text
        nameoff = common.get_dword(start_addr)
        ida_offset.op_plain_offset(start_addr,0,uncommontype.rtype.typelink.moduledata.types)
        nameaddr = uncommontype.rtype.typelink.moduledata.types+nameoff
        self.name = Name(nameaddr,uncommontype.rtype)
        ida_bytes.set_cmt(start_addr,"Type:%s;Type addr:0x%x;Method name:%s" % (self.uncommontype.rtype.name_str,self.uncommontype.rtype.start_addr,self.name.get_name()),False)
        typeoff = common.get_dword(start_addr+4)
        if typeoff == 0xffffffff:
            self.typeaddr = None
        else:
            ida_offset.op_plain_offset(start_addr+4,0,uncommontype.rtype.typelink.moduledata.types)
            self.typeaddr = uncommontype.rtype.typelink.moduledata.types+typeoff
        ifn_off = common.get_dword(start_addr+8)
        tfn_off = common.get_dword(start_addr+12)
        self.ifn_addr = text_addr+ifn_off
        self.tfn_addr = text_addr+tfn_off
        ida_offset.op_plain_offset(start_addr+8,0,text_addr)
        ida_offset.op_plain_offset(start_addr+12,0,text_addr)
        ida_bytes.set_cmt(start_addr+8,"interface call",False)
        ida_bytes.set_cmt(start_addr+12,"normal method call",False)



