from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.util.data.DataTypeParser import AllowedDataTypes
from ghidra.program.model.symbol import SymbolType, RefType
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType

def data_type_prompt():
    tool = state.getTool()
    dtm = currentProgram.getDataTypeManager()
    dialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
    tool.showDialog(dialog)
    data_type = dialog.getUserChosenDataType()
    return data_type
    
def retype_known_function_params():
    target_data_type = data_type_prompt()
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    task_mon = ConsoleTaskMonitor()
    # for every reference to every function
    for callee_func in currentProgram.getFunctionManager().getFunctions(True):
        callee_param_types = [param.getDataType() for param in callee_func.getParameters()]
        if len(callee_param_types) == 0:
            # callee doesn't even have params, nothing to do
            continue
        func_fixed = False
        for ref in callee_func.getSymbol().getReferences():
            if func_fixed:
                break
            # preliminary filtering
            if ref.getReferenceType() != RefType.UNCONDITIONAL_CALL:
                # not a call
                continue
            call_src = ref.getFromAddress()
            caller_func = getFunctionContaining(call_src)
            if not caller_func:
                # callsite not in function (probably UndefinedFunction)
                continue
            instr = getInstructionAt(call_src)
            if not instr:
                print("no instruction found at", call_src)
                return
            candidate = None
            # examine call
            for pcode in instr.getPcode():
                if pcode.getOpcode() != PcodeOp.CALL:
                    # sometimes the opcode is not actually a call and i don't know why
                    continue
                call_dst = pcode.getInput(0)
                if not call_dst or not call_dst.isAddress():
                    print("call destination not address??", call_src, pcode)
                    return
                if call_dst.getOffset() == caller_func.getEntryPoint().getOffset():
                    # recursive call, don't want to deal with these
                    continue
                # callsite is good for further inspection
                candidate = pcode
                break
            else:
                continue
            # need to decompile the function to get type info
            decomp_result = decompiler.decompileFunction(caller_func, 5, task_mon)
            if not decomp_result.decompileCompleted():
                print("decomp failed", caller_func)
                return
            hfunc = decomp_result.getHighFunction()
            pcode_it = hfunc.getPcodeOps(call_src.getPhysicalAddress())
            # find callsite again
            while pcode_it.hasNext():
                pcode = pcode_it.next()
                if pcode.getOpcode() != PcodeOp.CALL:
                    continue
                if pcode.getNumInputs() < 2:
                    # no args, nothing to do
                    continue
                if not pcode.getInput(0).getAddress().equals(callee_func.getEntryPoint()):
                    # not same callee
                    continue
                # search through arguments to find a matching type
                for i in range(1, min(len(callee_param_types), pcode.getNumInputs())):
                    callee_param_idx = i - 1
                    # they are probably being cast to another type so need to get the type before the cast
                    param = pcode.getInput(i)
                    inner_pcode = param.getDef()
                    if not inner_pcode:
                        continue
                    inner_node = inner_pcode.getInput(0)
                    inner_hvar = inner_node.getHigh()
                    if not inner_hvar:
                        continue
                    callee_param_type = callee_param_types[callee_param_idx]
                    if callee_param_type.equals(target_data_type):
                        # param is already same type, nothing to do
                        continue
                    if not inner_hvar.getDataType().equals(target_data_type):
                        # param not target type
                        continue
                    # found valid param, change its type
                    callee_params = callee_func.getParameters()
                    if callee_params[callee_param_idx].isAutoParameter():
                        print("could not modify param #{} of function {} because it is an autoparam".format(callee_param_idx, callee_func))
                        continue
                    callee_params[callee_param_idx].setDataType(target_data_type, SourceType.USER_DEFINED)
                    callee_func.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, False, SourceType.USER_DEFINED, callee_params)
                    print("changed function {} param #{} type because it was called with type \"{}\" at {} (param type was originally \"{}\")".format(
                        callee_func, callee_param_idx, target_data_type, call_src, callee_param_type))
                    func_fixed = True

retype_known_function_params()
