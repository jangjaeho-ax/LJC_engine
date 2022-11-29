import io
import json
import os
import getpass
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
        hf = get_high_function(func)
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
        for func in functions:
            vuln = dict()
            vuln['func_name'] = func.name
            vuln['address'] = str(addresses[func.name])
            injc_vuln_group[count] = vuln
            count = count + 1
        username = getpass.getuser()
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
        try:
            os.mkdir(folder_name)
        except OSError:
            print('File is already existed.')
        json_path = folder_name + json_name + '_results.json'
        print(json_path)
        with io.open(json_path, 'wb') as make_file:
            json.dump(injc_vuln_group, make_file)

if __name__ == "__main__":
    path = r"C:\Users\jjh96\_test.extracted\squashfs-root\lib\librtstream.so"
    sys_call_check(path)
