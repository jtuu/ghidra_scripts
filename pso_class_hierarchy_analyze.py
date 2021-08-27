import json
import sys
from ghidra.util import UndefinedFunction
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.lang import OperandType
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import SourceType

taskmon = ConsoleTaskMonitor()

def get_function_containing(addr):
    func = getFunctionContaining(addr)
    if func:
        return func
    func = UndefinedFunction.findFunction(currentProgram, addr, taskmon)
    if func:
        return func
    raise Exception("Could not find function containing " + addr.toString())

def data_that_reference_function(function):
    return [ref.getFromAddress()
                for ref in getReferencesTo(function.getEntryPoint())
                    if getDataAt(ref.getFromAddress())]

def functions_that_reference_memory(addr):
    return [get_function_containing(ref.getFromAddress())
                for ref in getReferencesTo(addr)
                    if getInstructionAt(ref.getFromAddress())]

def functions_that_call_function(callee):
    return [get_function_containing(ref.getFromAddress())
                for ref in getReferencesTo(callee.getEntryPoint())
                    if ref.getReferenceType().isCall()]

def data_is_vtable(orig_addr):
    # assumption: game objects have at least 4 methods and nothing directly behind them
    addr = orig_addr
    if addr.getOffset() < 4 or getDataAt(addr.subtract(4)):
        return False
    for i in range(4):
        data = getDataAt(addr)
        if not data or not data.isPointer():
            return False
        addr = addr.add(4)
    return True

def destructor_superclass_call_heuristic(vtable_ref, called_funcs):
    # assumption: superclass destructor must be called last or second to last
    # problem: getCalledFunctions() is unordered
    if len(called_funcs) > 1:
        if not func_eq(called_funcs[-1], vtable_ref) and not func_eq(called_funcs[-2], vtable_ref):
            return False
    elif len(called_funcs) == 1:
        if not func_eq(called_funcs[0], vtable_ref):
            return False
    else:
        raise Exception("No called funcs?")
    return True

def constructor_and_destructor_prelude_heuristic(func):
    # detect certain instructions that are always preset in constructors and destructors
    i = 0
    it = func.getBody().getAddresses(True)
    found_moveaxfs = False
    found_push1 = False
    while i < 10 and it.hasNext():
        cur = it.next()
        instr = getInstructionAt(cur)
        if not instr:
            continue
        i = i + 1
        if instr.toString() == "MOV EAX,FS:[0x0]":
            found_moveaxfs = True
        elif instr.toString() == "PUSH -0x1":
            found_push1 = True
    return found_moveaxfs and found_push1

unlikely_calls_from_destructor = [
    getFunctionAt(toAddr(0x00858736)), # `eh_vector_constructor_iterator'
    getFunctionAt(toAddr(0x0088fd17)), # `vector_constructor_iterator'
    getFunctionAt(toAddr(0x00859c55)), # _malloc
    getFunctionAt(toAddr(0x005caba4))  # allocate_in_main_arena
]
likely_calls_from_destructor = [
    getFunctionAt(toAddr(0x008586d6)), # `eh_vector_destructor_iterator'
    getFunctionAt(toAddr(0x0085a67c)), # `scalar_deleting_destructor'
    getFunctionAt(toAddr(0x00858882)), # _free
    getFunctionAt(toAddr(0x005c2f74)), # deallocate_in_main_arena
    getFunctionAt(toAddr(0x005c2f78))  # deallocate_in_main_arena_optcall
]

def destructor_calls_heuristic(called_funcs):
    likely = False
    unlikely = False
    for func in called_funcs:
        for f in likely_calls_from_destructor:
            if func_eq(func, f):
                likely = True
                break
        for f in unlikely_calls_from_destructor:
            if func_eq(func, f):
                unlikely = True
                break
    if unlikely and not likely:
        return False
    return True

def superdestructor_call_argument_heuristic(subdestr, superdestr):
    # find local "this"
    # ensure "this" is passed to superdestructor
    it = subdestr.getBody().getAddresses(True)
    local_this = None
    prev_instr = None
    while it.hasNext():
        cur = it.next()
        instr = getInstructionAt(cur)
        if not instr:
            continue
        pcode = instr.getPcode()
        if not local_this:
            # mov [ebp+x],ecx
            if (instr.getMnemonicString() == "MOV" and
                pcode[0].getOpcode() == PcodeOp.INT_ADD and
                pcode[0].getInput(0).isRegister() and # ebp
                pcode[0].getInput(1).isConstant() and
                pcode[1].getOpcode() == PcodeOp.COPY and
                pcode[1].getInput(0).isRegister() and
                pcode[1].getInput(0).getOffset() == 4): # ecx
                local_this = pcode[0].getInput(1) # stack offset
        else:
            if instr.getMnemonicString() == "CALL":
                flows = instr.getFlows()
                if not flows or len(flows) < 1:
                    continue
                call_target = flows[0]
                if call_target.equals(superdestr.getEntryPoint()):
                    # call to superdestructor
                    prev_pcode = prev_instr.getPcode()
                    # analyze previous instruction
                    for pcode in prev_pcode:
                        for inp in pcode.getInputs():
                            if inp.isRegister() and inp.getOffset() == 4:
                                # ecx was (probably) modified prior to call
                                return False
                    return True
        prev_instr = instr
    # analysis failed idk
    return True

def find_vtable_load(func):
    it = func.getBody().getAddresses(True)
    while it.hasNext():
        cur = it.next()
        instr = getInstructionAt(cur)
        if not instr:
            continue
        pcode = instr.getPcode()
        if instr.getMnemonicString() == "MOV" and len(pcode) > 1 and pcode[0].getOpcode() == PcodeOp.COPY and pcode[0].getInput(0).isConstant():
            copy_value = pcode[0].getInput(0)
            copy_dest = pcode[0].getOutput()
            if pcode[1].getOpcode() == PcodeOp.STORE and pcode[1].getInput(1).isRegister() and pcode[1].getInput(2).isUnique() and pcode[1].getInput(2).getOffset() == copy_dest.getOffset():
                return toAddr(copy_value.getOffset())
    return None

def func_eq(a, b):
    return a.getEntryPoint().equals(b.getEntryPoint())

class Class:
    def __init__(self, vtable_addr, depth, via = []):
        self.vtable_addr = vtable_addr
        self.subclasses = []
        self.subclass_set = set()
        self.depth = depth
        self.via = via
        # use user defined label if any
        label = getSymbolAt(vtable_addr)
        self.name = label.getName() if label and label.getSource().equals(SourceType.USER_DEFINED) else ""

    def add_subclass(self, subclass_vtable_addr, via = []):
        offset = subclass_vtable_addr.getOffset()
        if offset not in self.subclass_set:
            self.subclasses.append(Class(subclass_vtable_addr, self.depth + 1, via))
            self.subclass_set.add(offset)

    def resolve_subclasses(self):
        self.subclasses = []
        # contains my constructor, my destructor, (other?)
        # we want the destructor
        for vtable_ref in functions_that_reference_memory(self.vtable_addr):
            called_funcs = list(vtable_ref.getCalledFunctions(taskmon))

            if self.depth > 0:
                if not destructor_calls_heuristic(called_funcs):
                    continue

                if not constructor_and_destructor_prelude_heuristic(vtable_ref):
                    continue

            # contains subclass destructor, my deallocating destructor, (inlined destructors?)
            # we want the subclass destructor
            for vtable_ref_func_caller_func in vtable_ref.getCallingFunctions(taskmon):
                # destructor must always have references
                if len(getReferencesTo(vtable_ref_func_caller_func.getEntryPoint())) < 1:
                    continue

                if not superdestructor_call_argument_heuristic(vtable_ref_func_caller_func, vtable_ref):
                    continue

                called_funcs = list(vtable_ref_func_caller_func.getCalledFunctions(taskmon))

                if not destructor_calls_heuristic(called_funcs):
                    continue

                if not constructor_and_destructor_prelude_heuristic(vtable_ref_func_caller_func):
                    continue

                added_sub = False
                # contains subclass vtable, my vtable
                for data_ref in data_that_reference_function(vtable_ref_func_caller_func):
                    if not data_ref.equals(self.vtable_addr) and data_is_vtable(data_ref):
                        self.add_subclass(data_ref, [vtable_ref, vtable_ref_func_caller_func])
                        added_sub = True

                if not added_sub:
                    # not directly referenced in vtable, is this the "inner" destructor?
                    # try analyze the function body
                    vtable = find_vtable_load(vtable_ref_func_caller_func)
                    if vtable and not vtable.equals(self.vtable_addr) and data_is_vtable(vtable):
                        self.add_subclass(vtable, [vtable_ref, vtable_ref_func_caller_func])
                        added_sub = True
        return self.get_subclasses()

    def get_subclasses(self):
        return self.subclasses[:]

    def get_vtable_addr_int(self):
        return self.vtable_addr.getOffset()

    def to_dict(self):
        d = {
            "vtable": hex(int(self.vtable_addr.getOffset())),
            "subclasses": self.subclasses,
            "via": [hex(int(via.getEntryPoint().getOffset())) for via in self.via]
        }
        if self.name:
            d["name"] = self.name
        return d

    def to_json(self):
        return json.dumps(self.to_dict(), default = lambda x: x.to_dict(), indent = 2)

def resolve_class_tree(root_vtable):
    class_tree_root = Class(root_vtable, 0)
    stack = class_tree_root.resolve_subclasses()
    while len(stack):
        current_class = stack.pop()
        subclasses = current_class.resolve_subclasses()
        stack = stack + subclasses
    return class_tree_root

def print_class_tree(root):
    print("Class " + root.vtable_addr.toString())
    stack = root.get_subclasses()
    while len(stack):
        current = stack.pop()
        print("  " * current.depth + "Class " + current.vtable_addr.toString())
        stack = stack + current.get_subclasses()

base_game_object_vtable = toAddr(0x00b47a80)
tree = resolve_class_tree(base_game_object_vtable)
with open("pso_class_hierarchy.json", "w") as f:
    print >> f, tree.to_json()
