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

sources = [
    'snprintf',  # int snprintf ( char * s, size_t n, const char * format, ... );
    'sprintf',  # int sprintf  ( char * s, const char * format, ... );
]

sinks = [
    'system',  # int system(const char *command);
]

bitness_masks = {
    '16': 0xffff,
    '32': 0xffffffff,
    '64': 0xffffffffffffffff,
}
def int_overflow(func, ref):
    with pyhidra.open_program(path, project_location=r"C:\Users\jjh96\Desktop\reversing\exam",
                              analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        symbolTable =program.getSymbolTable()
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





def get_high_function(func , program):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(program)
    res = ifc.decompileFunction(func, 60, monitor)
    return res.getHighFunction()


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


def sys_call_check(path):
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
        # Step 1. Check if our target has at least one source and one sink we care about
        function_names = [func.name for func in functions]
        if (set(sources) & set(function_names)) and (set(sinks) & set(function_names)):
            print("This target contains interesting source(s) and sink(s). Continuing analysis...")
        else:
            print("This target does not contain interesting source(s) and sink(s). Done.")
            return

        # ====================================================================
        # Step 2. Find functions that calls at least one source and one sink
        interesting_functions = []
        for func in functions:
            monitor = ConsoleTaskMonitor()
            called_functions = func.getCalledFunctions(monitor)
            called_function_names = [cf.name for cf in called_functions]

            source_callers = set(called_function_names) & set(sources)
            sink_callers = set(called_function_names) & set(sinks)

            if source_callers and sink_callers:
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
        # Step 3. Dig into interesting functions
        for func in interesting_functions:
            print("\nAnalyzing function: {}".format(func.name))

            source_args = []
            sink_args = []

            hf = get_high_function(func, program)
            opiter = hf.getPcodeOps()
            while opiter.hasNext():
                op = opiter.next()
                mnemonic = op.getMnemonic()
                if mnemonic == "CALL":
                    opinputs = op.getInputs()
                    call_target = opinputs[0]
                    call_target_addr = call_target.getAddress()
                    call_target_name = fm.getFunctionAt(call_target_addr).getName()

                    if call_target_name == "system":
                        arg = opinputs[1]
                        sv = get_stack_var_from_varnode(func, arg, program)
                        if sv:
                            addr = op.getSeqnum().getTarget()
                            sink_args.append(sv.getName())
                            print("  >> {} : system({})".format(addr, sv.getName()))

                    elif call_target_name == "sprintf":
                        arg = opinputs[1]
                        sv = get_stack_var_from_varnode(func, arg, program)
                        if sv:
                            addr = op.getSeqnum().getTarget()
                            source_args.append(sv.getName())
                            print("  >> {} : sprintf({}, ...)".format(addr, sv.getName()))

                    elif call_target_name == "snprintf":
                        arg = opinputs[1]
                        sv = get_stack_var_from_varnode(func, arg, program)
                        if sv:
                            addr = op.getSeqnum().getTarget()
                            source_args.append(sv.getName())
                            print("  >> {} : snprintf({}, ...)".format(addr, sv.getName()))

            if len(set(sink_args) & set(source_args)) > 0:
                # dict for json dump
                vuln = dict()
                vuln['func_name'] = func.name
                vuln['address'] = str(addresses[func.name])
                injc_vuln_group[count] = vuln
                count = count + 1
                print(
                    "  [!] Alert: Function {} appears to contain a vulnerable `system` call pattern!".format(func.name))
        # _____________________store result to json file_____________________
        # get user name
        username = getpass.getuser()
        # get program name
        program_path = str(program.getExecutablePath())
        target = '\\'
        index = -1
        while True:
            ret = program_path.find(target, index + 1)
            if ret == -1:
                break
            index = ret
        # print('start=%d' % index)
        json_name = program_path[index:] + '_result.json'
        folder_name = 'C:\\Users\\' + username + '\\results'
        # create folder for results
        try:
            os.mkdir(folder_name)
        except OSError:
            print('File is already existed.')
        json_path = folder_name + json_name + '_results.json'
        with io.open(json_path, 'w') as make_file:
            json.dump(injc_vuln_group, make_file)
        print(injc_vuln_group)


if __name__ == "__main__":
    path = r"C:\Users\jjh96\_test.extracted\squashfs-root\lib\librtstream.so"
    sys_call_check(path)