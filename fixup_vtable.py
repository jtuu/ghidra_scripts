#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.util import UndefinedFunction
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
def get_or_create_function(addr):
    tm = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()
    fn = fm.getFunctionAt(addr)
    new_fn_name = "FUN_" + addr.toString()
    if fn:
        return fn
    else:
        orig_fn = UndefinedFunction.findFunctionUsingSimpleBlockModel(currentProgram, addr, tm)
        if not orig_fn:
            raise Exception("Failed to find function at " + addr.toString())
        entry = addr
        start = addr
        end = addr
        while True:
            addr = addr.add(1)
            fn = UndefinedFunction.findFunctionUsingSimpleBlockModel(currentProgram, addr, tm)
            if not fn or not fn.equals(orig_fn):
                break
            end = addr
        return fm.createFunction(new_fn_name, entry, AddressSet(start, end), SourceType.USER_DEFINED)

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.data import Pointer32DataType

def fixup_vtable(class_name, start, ns = None):
    class_search_result = getDataTypes(class_name)
    if len(class_search_result) == 0:
        raise Exception("No type found matching " + class_name)
    if len(class_search_result) > 1:
        raise Exception("Too many types found matching " + class_name)
    class_type = class_search_result[0]
    class_ptr_type = Pointer32DataType(class_type)
    vtable = getDataAt(toAddr(start))
    i = 0
    method_addr = vtable.getComponent(i)
    while method_addr:
        method_addr = method_addr.getValue()
        method = get_or_create_function(method_addr)
        if ns:
            method.setParentNamespace(ns)
        if method.getCallingConventionName() != "__thiscall":
            method.setCallingConvention("__thiscall")
        if not method.hasCustomVariableStorage():
            method.setCustomVariableStorage(True)
        params = method.getParameters()
        this_param = params[0]
        if this_param.isAutoParameter():
            print("this still autoparam? skipping " + method.getName())
            continue
        if not this_param.getFormalDataType().equals(class_ptr_type):
            this_param.setDataType(class_ptr_type, SourceType.USER_DEFINED)
            method.replaceParameters(list(params), FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)
        i = i + 1
        method_addr = vtable.getComponent(i)

fixup_vtable("AutoClass1", 0x00b39460)
