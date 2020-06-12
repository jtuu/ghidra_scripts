from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.util.data.DataTypeParser import AllowedDataTypes
from ghidra.formats.gfilesystem import SelectFromListDialog
from ghidra.program.model.data import Enum
from java.util.function import Function
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.util.datastruct import CallbackAccumulator
from java.util.function import Consumer
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import PointerDataType

def search_pcode(root, test):
    stack = root.getInputs()
    out = root.getOutput()
    if out is not None:
        stack.append(out)
    while len(stack) > 0:
        node = stack.pop()
        if test(node):
            return True
        pcode = node.getDef()
        if pcode:
            stack.extend(pcode.getInputs())
    return False

class func(Function):
    def __init__(self, fn):
        self.apply = fn

class EnumMemberFinder(Consumer):
    def __init__(self, task_mon, enum_type, member_value):
        self.task_mon = task_mon
        self.enum_type = enum_type
        self.member_value = member_value
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(currentProgram)
        self.decompiler.toggleCCode(False)

    def visit(self, node):
        if not node.isConstant():
            return False
        hvar = node.getHigh()
        if not hvar:
            return False
        dt = hvar.getDataType()
        i = 0
        while isinstance(dt, PointerDataType) and i < 10:
            dt = dt.getDataType()
            i += 1
        if not dt.equals(self.enum_type):
            return False
        scalar = hvar.getScalar()
        if not scalar:
            return False
        if scalar.getUnsignedValue() != self.member_value:
            return False
        print(hvar.getPCAddress())
        return True

    def accept(self, ref):
        ref_addr = ref.getLocationOfUse()
        ref_func = getFunctionContaining(ref_addr)
        func_addr = ref_func.getEntryPoint()
        if not ref_func:
            print("reference not in function", ref_addr)
            return
        decomp_result = self.decompiler.decompileFunction(ref_func, 5, self.task_mon)
        if not decomp_result.decompileCompleted():
            print("decomp failed", ref_func)
            return
        hfunc = decomp_result.getHighFunction()
        pcode_it = hfunc.getPcodeOps(ref_addr.getPhysicalAddress())
        while pcode_it.hasNext():
            if search_pcode(pcode_it.next(), self.visit):
                return

def data_type_prompt():
    tool = state.getTool()
    dtm = currentProgram.getDataTypeManager()
    dialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
    tool.showDialog(dialog)
    data_type = dialog.getUserChosenDataType()
    return data_type

def list_select_prompt(title, text, items, stringifier = None):
    if stringifier is None:
        stringifier = func(lambda x: x)
    tool = state.getTool()
    return SelectFromListDialog.selectFromList(items, title, text, stringifier)

def find_enum_member():
    dt = data_type_prompt()
    if not isinstance(dt, Enum):
        print("data type is not an enum")
        return
    member = list_select_prompt("find_enum_member.py", "Select enum member to search for", list(dt.getValues()), func(lambda val: dt.getName(val)))
    if not member:
        print("invalid member selected")
        return
    task_mon = ConsoleTaskMonitor()
    print("References to {}.{}:".format(dt.getName(), dt.getName(member)))
    ReferenceUtils.findDataTypeReferences(CallbackAccumulator(EnumMemberFinder(task_mon, dt, member)), dt, None, currentProgram, task_mon)

find_enum_member()
