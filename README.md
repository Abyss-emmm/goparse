# 0x0 goparse
parse golang bin

# 0x1 use
IDA:Alt+F7,choose main.py

You will get a global variable `firstmodule`，script will parse moduledata、pcHeader、funcinfo、typelinks、itablinks。

## 1.1 Get funcinfo
```python
#func_addr is int
print(firstmodule.pcHeader.funcs[<func_addr>])
```

## 1.2 Get type
```python
parsed_types = firstmoduledata.typelinks.parsed_types
#type_addr is int
some_type = parsed_types[<type_addr>]
#kind
some_type.get_kind()
#name
# if name is start with '#' means this type is exported
#because if type is exported，type'nams will start with one '*'
#if ptr type is not exported,its name will also start with one '*'
#so if type's name start with only one '*',can't confirm this type is exported or just is ptr type which is not exported。
#therefor change '*' to '#' if type is exported
some_type.name.get_name()
```
### 1.2.1 Struct
```python
#some_type.get_kind() == "Struct"

#show struct define like go and know the offset
some_type.show_struct()

#generate struct in IDA
some_type.generate_struct()
```

## 1.3 parse typelink
```python
firstmodule.parse_typelink()
structs = firstmodule.rtypes['Struct']
structs['#http.Client']  #if name is same,just get the last one,or you can get struct with its addr
```
