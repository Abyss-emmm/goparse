#encoding:utf-8

import idaapi
from pcHeader import pcHeader
idaapi.require("pcHeader")
idaapi.require("func")
idaapi.require("moduledata")
idaapi.require("common")

def printhex(addr):
    print(hex(addr))

def main():
    pcheader_addrs = common.find_addr()
    pcheader_moduledata_addr = []
    for entry in pcheader_addrs:
        for moduledata_addr in entry['ref_from']:
            pcheader_addr = entry['addr']
            if pcHeader.pcHeader.is_valid(pcheader_addr,moduledata_addr):
                pcheader_moduledata_addr.append({"pcheader":pcheader_addr,"moduledata":moduledata_addr})
    if len(pcheader_moduledata_addr) == 0:
        print("Can't find pcheader")
    else:
        for addr in pcheader_moduledata_addr:
            print("pcheader:0x%X moduledata:0x%x" % (addr['pcheader'],addr["moduledata"]))
        if len(pcheader_moduledata_addr) == 1:
            firstmoduledata = moduledata.ModuleData(pcheader_moduledata_addr[0]["moduledata"])
            return firstmoduledata



firstmoduledata = main()
