# Checks system calls for command injection pattern
import io
import json
import getpass
import os
import pyhidra
pyhidra.start()

import ghidra
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import VarnodeAST
from ghidra.util.task import ConsoleTaskMonitor


sinks = [
    'memcpy'
]


#함수를 디컴파일 하여 pcode를 얻을 수 있도록 한다.
def get_high_function(func , program):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(program)
    res = ifc.decompileFunction(func, 60, monitor)
    return res.getHighFunction()

'''
def get_stack_var_from_varnode(func, varnode, program):
    if type(varnode) not in [Varnode, VarnodeAST]:
        raise Exception(
            "Invalid value passed to get_stack_var_from_varnode(). Expected `Varnode` or `VarnodeAST`, got {}.".format(
                type(varnode)))

    bitmask = bitness_masks[program.getMetadata()['Address Size']]

    local_variables = func.getAllVariables()
    vndef = varnode.getDef()
    if vndef:
        vndef_inputs = vndef.getInputs()
        for defop_input in vndef_inputs:
            defop_input_offset = defop_input.getAddress().getOffset() & bitmask
            for lv in local_variables:
                unsigned_lv_offset = lv.getMinAddress().getUnsignedOffset() & bitmask
                if unsigned_lv_offset == defop_input_offset:
                    return lv

        # If we get here, varnode is likely a "acStack##" variable.
        hf = get_high_function(func, program)
        lsm = hf.getLocalSymbolMap()

        for vndef_input in vndef_inputs:
            defop_input_offset = vndef_input.getAddress().getOffset() & bitmask
            for symbol in lsm.getSymbols():
                if symbol.isParameter():
                    continue
                if defop_input_offset == symbol.getStorage().getFirstVarnode().getOffset() & bitmask:
                    return symbol

    # unable to resolve stack variable for given varnode
    return None
'''




def check_int_overflow(path):
    result = {}
    text = []
    num = 0


    with pyhidra.open_program(path, project_location=r"C:\Users\jjh96\Desktop\reversing\exam",
                              analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        functions = [func for func in fm.getFunctions(True)]
        # vuln group for json dump
        injc_vuln_group = dict()
        # store all entry points of function
        addresses = {}
        count = 0
        for function in functions:
            try:
                addresses[function.name].append(function.getEntryPoint())
            except:
                addresses[function.name] = []
                addresses[function.name].append(function.getEntryPoint())
        # ====================================================================
        # source와 sink가 function name에 있는지 확인
        function_names = [func.name for func in functions]

        if  (set(sinks) & set(function_names)):
            print("This target contains interesting source(s) and sink(s). Continuing analysis...")
        else:
            print("This target does not contain interesting source(s) and sink(s). Done.")
            return

        # ====================================================================
        #sink와 source를 call하는 함수를 찾음
        interesting_functions = []
        for func in functions:

            monitor = ConsoleTaskMonitor()
            called_functions = func.getCalledFunctions(monitor)

            called_function_names = [cf.name for cf in called_functions]

            sink_callers = set(called_function_names) & set(sinks)

            if sink_callers:
                interesting_functions.append(func)

        # Show any interesting functions found
        if len(interesting_functions) <= 0:
            print("\nNo interesting functions found to analyze. Done.")
            return
        else:
            print("\nFound {} interesting functions to analyze:".format(len(interesting_functions)))
            for func in interesting_functions:
                print("  {}".format(func.name))

        # ====================================================================
        # 위에서 찾은 interesting functions을 분석하는 단계
        for func in interesting_functions:
            print("\nAnalyzing function: {}".format(func.name))
            hf = get_high_function(func, program)
            opiter = hf.getPcodeOps()
            op = None
            signed_comparison_varnodes = set()

            while opiter.hasNext():
                op = opiter.next()
                mnemonic = op.getMnemonic()
                if (op.getOpcode() == ghidra.program.model.pcode.PcodeOp.INT_SLESS) or (
                        op.getOpcode() == ghidra.program.model.pcode.PcodeOp.INT_LESS):
                    print(op)
                    for v in op.getInputs():
                        if v.isConstant():
                            continue
                        signed_comparison_varnodes.add(v)
                        # print(v)
                        # print(v.isRegister())
                    print(signed_comparison_varnodes)

                if op.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALL:
                    continue
                inputs = op.getInputs()
                call_site = inputs[0]

                # 주소가 아닌 경우 continue
                if call_site.isAddress() == False:
                    continue

                call_offset = call_site.getOffset()
                func_offset = func.getEntryPoint().getOffset()


                if call_offset != func_offset:
                    continue
                if len(inputs) != 4:
                    continue
                size_varnode = inputs[-1]
                def_pcode = size_varnode.getDef()

                if def_pcode is None:
                    continue

                for v in def_pcode.getInputs():
                    if v in signed_comparison_varnodes:
                        num += 1
                        print(
                            "  [!] Alert: Function {} appears to contain a vulnerable Int overflow pattern!".format(
                                func.name))
                        text.append(
                            str("  [!] Alert: Function {} appears to contain a vulnerable Int overflow pattern!".format(
                                func.name)) + '\n')

                print("\n\ncall time\n\n")
                print(op)
                print(size_varnode)

        result['text'] = text
        result['num'] = num
        return result


if __name__ == "__main__":
    path = r"C:\Users\jjh96\Desktop\reversing\test\intOver.exe"
    check_int_overflow(path)