import re
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.block import BasicBlockModel

taskmon = ConsoleTaskMonitor()
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
decompiler.toggleCCode(True)
blockmodel = BasicBlockModel(currentProgram)

def basic_blocks(func):
    return blockmodel.getCodeBlocksContaining(func.getBody(), taskmon)

def decompile(func):
    return decompiler.decompileFunction(func, 5, taskmon)

def refs_of_type(addr, type):
    return (ref for ref in getReferencesTo(addr) if ref.getReferenceType() == type)

def unconditional_calls(func):
    return (ref.getFromAddress() for ref in refs_of_type(func.getEntryPoint(), RefType.UNCONDITIONAL_CALL))

def first_register_param(func):
    "Finds the first parameter that uses a regular register for its storage and returns that parameter"
    for param in func.getParameters():
        regs = param.getVariableStorage().getRegisters()
        if regs and len(regs) == 1:
            reg = regs[0]
            name = reg.getName()
            # Detect register type based on its name
            if name and len(name) and name[0] == "r":
                return param
    return None

def emulate(func):
    emuhelper.writeRegister(emuhelper.getPCRegister(), func.getEntryPoint().getOffset())
    emuhelper.step()
    return

def find_offset_store(hfunc, register, offset):
    "Finds value of first store into given offset in given register"
    it = hfunc.getPcodeOps()
    #while it.hasNext():
    for pcode in hfunc.getLocalSymbolMap().getParam(0).getInstances()[0].getDescendants():
        #pcode = it.next()
        inputs = pcode.getInputs()
        if not inputs or len(inputs) < 1:
            continue
        print(pcode.getSeqnum())
        for i in pcode.getOutput().getDef().getInputs():
            print(i.getDef())
        first = inputs[0]
        last = inputs[-1]
        found_register = False
        found_offset = False
        if not first.isUnique():
            continue
        d = first.getDef()
        if not d:
            continue
        dinputs = d.getInputs()
        for dinp in dinputs:
            if dinp.isRegister():
                if dinp.getOffset() == register.getOffset():
                    found_register = True
                break
        if not found_register:
            continue
        for dinp in dinputs:
            if dinp.isConstant():
                if dinp.getOffset() == offset:
                    found_offset = True
                break
        if not found_offset:
            continue
        return last.getDef().getInputs()[-1].getAddress()
    return None

def indirect_call_offset(instrs):
    if instrs[-1].getMnemonicString().upper() != "BCTRL" or instrs[-2].getMnemonicString().upper() != "MTSPR" or instrs[-3].getMnemonicString().upper() != "LWZ":
        print(instrs)
        raise Exception("Indirect call not well formed")
    mtspr_pcodes = instrs[-2].getPcode()
    mtspr_out = mtspr_pcodes[0].getOutput()
    if not mtspr_out.isRegister() or mtspr_out.getOffset() != 0x1024:
        return
    mtspr_in = mtspr_pcodes[0].getInputs()[0]
    if not mtspr_in.isRegister():
        return
    offset_register_offset = mtspr_in.getOffset()
    lwz_pcodes = instrs[-3].getPcode()
    call_offset = None
    for pcode in lwz_pcodes:
        if pcode.getOpcode() != PcodeOp.INT_ADD:
            continue
        for inp in pcode.getInputs():
            if inp.isRegister() and inp.getOffset() != offset_register_offset:
                return
            if call_offset is None and inp.isConstant():
                call_offset = inp.getOffset()
    return call_offset

class Class:
    def __init__(self, ctor, name, parent):
        self.ctor = ctor
        self.name = name
        self.parent = parent
        self.children = []
        self.this_param = first_register_param(ctor)
        self.ctor_decomp = None
        self.vtable = None
    
    def get_ctor_decomp(self):
        if self.ctor_decomp:
            return self.ctor_decomp

        result = decompile(self.ctor)
        if result.decompileCompleted():
            self.ctor_decomp = result
            return result

        return None
    
    def find_name_from_decomp(self, decompiled_func):
        pat = "\\*" + self.this_param.getName() + " = (.+);"
        match = re.search(pat, decompiled_func.getDecompiledFunction().getC())
        if match and match.group(1):
            symname = match.group(1)
            syms = getSymbols(symname, None)
            if syms and len(syms) > 0:
                sym = syms[0]
                ptr = getDataAt(sym.getAddress())
                if ptr.isPointer():
                    data = getDataAt(ptr.getValue())
                    if data is None:
                        print([sym, data])
                    return str(getDataAt(ptr.getValue()).getValue())
                else:
                    a = toAddr(ptr.getValue().getUnsignedValue())
                    data = getDataAt(a)
                    if data is None:
                        createAsciiString(a)
                        data = getDataAt(a)
                    return str(data.getValue())
        return None
    
    def resolve_indirect_call(self, offset):
        if self.vtable is None:
            self.vtable = self.find_vtable()
        return getFunctionAt(getDataAt(toAddr(self.vtable.getOffset() + offset)).getValue())

    def find_vtable_from_decomp(self, decompiled_func):
        pat = self.this_param.getName() + "\[6\] = &(.+);"
        match = re.search(pat, decompiled_func.getDecompiledFunction().getC())
        if not match or not match.group(1):
            return None
        symname = match.group(1)
        syms = getSymbols(symname, None)
        if not syms or len(syms) < 1:
            return None
        sym = syms[0]
        return sym.getAddress()
    
    def find_vtable(self):
        return self.find_vtable_from_decomp(self.get_ctor_decomp())

    def find_name(self):
        if not self.this_param:
            return "Invalid"
        name = self.find_name_from_decomp(self.get_ctor_decomp())
        if name:
            return name
        if not self.parent:
            return "NoParent"
        # also look inside function calls after supercall
        first_block = next(basic_blocks(self.ctor))
        it = first_block.getFirstRange().iterator()
        after_supercall = False
        instructions = []
        subfunc = None
        while it.hasNext():
            cur = it.next()
            instr = getInstructionAt(cur)
            if not instr:
                continue
            instructions.append(instr)
            pcodes = instr.getPcode()
            if instr.getMnemonicString().upper() == "BCTRL":
                call_offset = indirect_call_offset(instructions)
                subfunc = self.resolve_indirect_call(call_offset)
            elif instr.getMnemonicString().upper() == "BL":
                if not pcodes or len(pcodes) < 1:
                    continue
                last = pcodes[-1]
                if last.getOpcode() != PcodeOp.CALL:
                    continue
                inputs = last.getInputs()
                if not inputs or len(inputs) < 1:
                    continue
                subfunc = getFunctionAt(inputs[0].getAddress())
            else:
                continue
            if after_supercall:
                name = self.find_name_from_decomp(decompile(subfunc))
                if name:
                    return name
            else:
                after_supercall = subfunc == self.parent.ctor
        return "Unnamed_" + str(self.ctor.getEntryPoint())
    
    def subconstructor_heuristic_first_params_match(self):
        """Theory: A subconstructor can be detected by checking if its
        first parameter is passed as the first argument to the superconstructor."""
        return self.parent and self.this_param and self.this_param.getVariableStorage().equals(self.parent.this_param.getVariableStorage())
    
    def subconstructor_heuristic_first_call(self):
        """Shown to be incorrect by FUN_800fca48.
        Theory: A subconstructor can be detected by checking if the
        call to the superconstructor is the first call in the function."""
        if not self.parent:
            return False

        i = 0
        it = self.ctor.getBody().getAddresses(True)
        while i < 20 and it.hasNext():
            cur = it.next()
            instr = getInstructionAt(cur)
            if not instr:
                continue
            i = i + 1
            if instr.getMnemonicString().upper() != "BL":
                continue
            pcodes = instr.getPcode()
            if not pcodes or len(pcodes) < 1:
                continue
            last = instr.getPcode()[-1]
            if last.getOpcode() != PcodeOp.CALL:
                continue
            inputs = last.getInputs()
            if not inputs or len(inputs) < 1:
                continue
            return inputs[0].getAddress() == self.parent.ctor.getEntryPoint()
        return False
    
    def subconstructor_heuristic_first_basicblock(self):
        """Theory: Call to superconstructor is within first basic block."""
        if not self.parent:
            return False
        
        first_block = next(basic_blocks(self.ctor))
        it = first_block.getFirstRange().iterator()
        while it.hasNext():
            cur = it.next()
            instr = getInstructionAt(cur)
            if not instr:
                continue
            if instr.getMnemonicString().upper() != "BL":
                continue
            pcodes = instr.getPcode()
            if not pcodes or len(pcodes) < 1:
                continue
            last = instr.getPcode()[-1]
            if last.getOpcode() != PcodeOp.CALL:
                continue
            inputs = last.getInputs()
            if not inputs or len(inputs) < 1:
                continue
            if inputs[0].getAddress() == self.parent.ctor.getEntryPoint():
                return True
        return False

    def to_string(self):
        parent_str = self.parent.to_string() if self.parent else "None"
        if self.name:
            return parent_str + " -> " + self.name + "( " + str(self.ctor) + " )"
        else:
            return parent_str + " -> " + str(self.ctor)

def analyze(superclass):
    if not superclass.this_param:
        return None

    # Find subconstructors among calls to superconstructor
    for call_addr in unconditional_calls(superclass.ctor):
        calling_func = getFunctionContaining(call_addr)
        subclass = Class(calling_func, None, superclass)

        is_subctor = (
            subclass.subconstructor_heuristic_first_params_match()
            and subclass.subconstructor_heuristic_first_basicblock())

        if is_subctor:
            subclass.name = subclass.find_name()
            superclass.children.append(subclass)
            analyze(subclass)
        else:
            subclass.name = "Fail"

def print_class_declarations(current, file):
    print >> file, "class " + current.name,
    if current.parent:
        print >> f, ": public " + current.parent.name,
    print >> file, "{};"
    for child in current.children:
        print_class_declarations(child, file)

def print_names(current, file):
    print >> file, current.name
    for child in current.children:
        names(child, f)

TObject = Class(getFunctionAt(toAddr(0x8022a424)), "TObject", None)
analyze(TObject)

with open("psogc_class_declarations.txt", "w") as f:
    print_class_declarations(TObject, f)
