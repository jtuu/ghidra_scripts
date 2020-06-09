from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.util.data.DataTypeParser import AllowedDataTypes
from ghidra.program.model.symbol import SymbolType, RefType
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.util.datastruct import CallbackAccumulator
from java.util.function import Consumer
from ghidra.program.model.data import Pointer
from ghidra.program.model.listing import ParameterImpl

def is_pointer(dt):
    return isinstance(dt, Pointer)

def wrapper_ops_for_type(dt):
    ops = [PcodeOp.CAST]
    if not is_pointer(dt) and dt.getLength() > 1:
        ops.extend([PcodeOp.SEXT, PcodeOp.ZEXT])
    return ops

class DataTypeReferenceConsumer(Consumer):
    def __init__(self, task_mon, target_data_type):
        self.task_mon = task_mon
        self.target_data_type = target_data_type
        self.wrapper_ops = wrapper_ops_for_type(target_data_type)
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(currentProgram)
        self.retyped = set()

    def accept(self, ref):
        retype_known_function_params_at(self.decompiler, self.task_mon, self.target_data_type, self.wrapper_ops, ref.getLocationOfUse(), self.retyped)

def unwrap_vnode(vnode, wrappers):
    pcode = vnode.getDef()
    while pcode and pcode.getOpcode() in wrappers:
        vnode = pcode.getInput(0)
        pcode = vnode.getDef()
    return vnode

def valid_param(param, target_data_type):
    return param.getDataType().getLength() >= target_data_type.getLength() and \
           not param.getDataType().equals(target_data_type) and \
           param.getSource() != SourceType.USER_DEFINED

def retype_known_function_params_at(decompiler, task_mon, target_data_type, wrapper_ops, call_src, retyped=None):
    # preliminary filtering
    caller_func = getFunctionContaining(call_src)
    if not caller_func:
        # reference not in function
        return
    instr = getInstructionAt(call_src)
    if not instr:
        print("no instruction found at", call_src)
        return
    if instr.getMnemonicString() != "CALL":
        return
    candidate = None
    callee_func = None
    # examine call
    for pcode in instr.getPcode():
        if pcode.getOpcode() != PcodeOp.CALL:
            continue
        call_dst = pcode.getInput(0)
        if not call_dst or not call_dst.isAddress():
            print("call destination not address??", call_src, pcode)
            return
        callee_func = getFunctionAt(toAddr(call_dst.getOffset()))
        if not callee_func:
            print("no function found at call destination??", call_src)
            return
        if callee_func.equals(caller_func):
            # recursive call, don't want to deal with these
            continue

        # callsite is good for further inspection
        candidate = pcode
        break
    else:
        # no callsite found for this reference
        return
    callee_params = callee_func.getParameters()
    if len(callee_params) == 0:
        # callee doesn't even have params, nothing to do
        return
    if not any(valid_param(param, target_data_type) for param in callee_params):
        # none of the callee params are valid
        return
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
        # first index is skipped because it is the call destination
        for i in range(1, pcode.getNumInputs()):
            callee_param_idx = i - 1
            callee_param = callee_params[callee_param_idx]
            callee_param_type = callee_param.getDataType()
            if callee_param_idx >= len(callee_params):
                # too many arguments given
                return
            if not valid_param(callee_param, target_data_type):
                continue
            # try find base type of call arg
            param = pcode.getInput(i)
            unwrapped = unwrap_vnode(param, wrapper_ops)
            hvar = unwrapped.getHigh()
            if not hvar:
                continue
            dt = hvar.getDataType()
            if not dt.equals(target_data_type):
                # param not target type
                continue
            # found valid param, change its type
            update_type = FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS
            if callee_param.isAutoParameter():
                callee_func.setCustomVariableStorage(True)
                update_type = FunctionUpdateType.CUSTOM_STORAGE
            callee_params[callee_param_idx] = ParameterImpl(callee_params[callee_param_idx], currentProgram)
            callee_params[callee_param_idx].setDataType(target_data_type, SourceType.USER_DEFINED)
            try:
                callee_func.replaceParameters(update_type, False, SourceType.USER_DEFINED, callee_params)
            except Exception as ex:
                print("failed to change parameter #{} of function {} (called from {})".format(callee_param_idx, callee_func, call_src))
                raise ex
            if retyped is not None:
                retyped.add(callee_func)
            print("changed function {} param #{} type because it was called with type \"{}\" at {} (param type was originally \"{}\")".format(
                callee_func, callee_param_idx, target_data_type, call_src, callee_param_type))

def data_type_prompt():
    tool = state.getTool()
    dtm = currentProgram.getDataTypeManager()
    dialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
    tool.showDialog(dialog)
    data_type = dialog.getUserChosenDataType()
    return data_type
    
def retype_known_function_params():
    target_data_type = data_type_prompt()
    if not target_data_type:
        print("invalid data type")
        return
    task_mon = ConsoleTaskMonitor()
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    i = 0
    while True:
        print("round {}".format(i))
        consumer = DataTypeReferenceConsumer(task_mon, target_data_type)
        ReferenceUtils.findDataTypeReferences(CallbackAccumulator(consumer), target_data_type, None, currentProgram, task_mon)
        if len(consumer.retyped) == 0:
            break
        i += 1
    

retype_known_function_params()
