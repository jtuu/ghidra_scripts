from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import ParameterImpl, VariableStorage

def fixup_optimized_callee_params():
    all_funcs = list(currentProgram.getFunctionManager().getFunctionsNoStubs(True))
    num_fixed = 0

    # search all functions in program
    for func in all_funcs:
        func_body = func.getBody()
        register_stack_pairs = []
        instr = getInstructionAt(func.getEntryPoint())
        last_instr = instr

        if not instr:
            continue

        # find functions whose instructions are all `mov register, stack`
        while instr and func_body.contains(instr.getAddress()):
            # is mov?
            if instr.getMnemonicString() != "MOV":
                break
            # into register?
            register = instr.getRegister(0)
            if not register:
                break
            second_op_refs = list(instr.getOperandReferences(1))
            if len(second_op_refs) != 1:
                break
            to_addr = second_op_refs[0].getToAddress()
            # from stack?
            if not to_addr or not to_addr.isStackAddress():
                break
            # save mov operands
            register_stack_pairs.append((register, to_addr.getOffset()))
            last_instr = instr
            instr = instr.getNext()
        else:
            # found what we're looking for

            register_stack_pairs.sort(key = lambda n: n[1])

            optimized_callee = getFunctionAt(last_instr.getMaxAddress().add(1))

            optimized_callee.setName(func.getName() + "_optcall", SourceType.USER_DEFINED)
            optimized_callee.setCustomVariableStorage(True)

            formal_params = func.getParameters()
            new_params = []
            # match registers to stack params and construct new params
            for (register, stack_offset) in register_stack_pairs:
                param_idx = None
                for (i, param) in enumerate(formal_params):
                    if param.getLength() > 4:
                        print("large param at", func.getEntryPoint())
                        return

                    if param.isStackVariable() and stack_offset == param.getStackOffset():
                        param_idx = i
                        break
                else:
                    print("no matching param found", func.getEntryPoint(), register, stack_offset)
                    break
                param = formal_params[param_idx]
                prog = param.getProgram()
                new_params.append(ParameterImpl(param.getName(), param.getDataType(), VariableStorage(prog, [register]), prog))
                del formal_params[param_idx]
            # set params
            optimized_callee.replaceParameters(new_params, FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)

            orig_ret = func.getReturnType()
            opt_ret = optimized_callee.getReturnType()

            if orig_ret.getLength() > 4:
                print("large ret at", func.getEntryPoint())
            elif orig_ret.getLength() == opt_ret.getLength() or opt_ret.getName() == "undefined":
                optimized_callee.setReturnType(orig_ret, SourceType.USER_DEFINED)
            else:
                print("could not set return type because of size mismatch", func.getEntryPoint(), orig_ret.getLength(), opt_ret.getLength())

            print("fixed", func.getEntryPoint())
            num_fixed += 1

    print("fixed {} functions".format(num_fixed))

fixup_optimized_callee_params()
