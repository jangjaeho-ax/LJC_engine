import io
import json
import getpass
import os
import pyhidra
from pprint import pprint as pp
pyhidra.start()


import ghidra
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import VarnodeAST
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.plugin.core.osgi import BundleHost
#CWE-674 패턴을 검출 코드
sources = [
    'INT_EQUAL',
    'INT_NOTEQUAL',
    'INT_LESS',
    'INT_SLESS',
    'INT_LESSEQUAL',
    'INT_SLESSEQUAL',
    'INT_SLESSEQUAL',
    'FLOAT_EQUAL',
    'FLOAT_NOTEQUAL',
    'FLOAT_LESS',
    'FLOAT_LESSEQUAL',
    'FLOAT_NAN',
]
sinks = [
    'INT_DIV',
    'INT_SDIV',
    'FLOAT_DIV',
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

def check_sys_call(path):
    result = {}
    text = []
    num = 0

    with pyhidra.open_program(path, project_location=r".\exam",
                              analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        #flat_api.analyzeAll(program)
        fm = program.getFunctionManager()
        functions = [func for func in fm.getFunctions(True)]

        interesting_functions = []
        for function in functions:
            if function.isExternal() is False:
                interesting_functions.append(function)
        print(len(functions))
        print(len(interesting_functions))

        if len(interesting_functions) <= 0:
            print("\nNo interesting functions found to analyze. Done.")
            text.append("\nNo interesting functions found to analyze. Done." + '\n')
            result['text'] = text
            result['num'] = num
            return result
        else:
            print("\nFound {} interesting functions to analyze:".format(len(interesting_functions)))
            text.append(str("\nFound {} interesting functions to analyze:".format(len(interesting_functions))) + '\n')
            for func in interesting_functions:
                print("  {}".format(func.name))
                text.append(str("  {}".format(func.name)) + '\n')
        # ====================================================================
        # interesting function을 분석
        for func in interesting_functions:
            print("\nAnalyzing function: {}".format(func.name))
            text.append(str("\nAnalyzing function: {}".format(func.name)) + '\n')
            #local_variables = func.getAllVariables()
            #print(local_variables)
            #print('\n\n')
            sinks_args = []
            sources_args = []
            interesting_args = []
            # 함수를 디컴파일 해서 pcode를 가져올수 있게 만듬
            hf = get_high_function(func, program)
            opiter = hf.getPcodeOps()
            while opiter.hasNext():
                op = opiter.next()
                mnemonic = op.getMnemonic()
                #print(op)
                if mnemonic in sinks:
                    opinputs =op.getInputs()
                    sinks_args.append(opinputs[1])
                elif mnemonic in sources:
                    sources_args = op.getInputs()
            for s in sinks_args:
                if s in sources_args:
                    interesting_args.append(s)
            if interesting_args is None:
                print("  Function {} is Safe".format(func.name))
                text.append(
                    str("  Function {} is Safe".format(func.name)) + '\n')
                result['text'] = text
                result['num'] = num
                return result
            else:
                print(
                    "  [!] Alert: Function {} appears to contain a 'Div Zero' pattern!".format(func.name))
                text.append(
                    str("  [!] Alert: Function {} appears to contain a 'Div Zero' pattern!".format(
                        func.name)) + '\n')



        result['text'] = text
        result['num'] = num
        return result

if __name__ == "__main__":
    path = r"C:\Users\jjh96\Desktop\reversing\test\endless.exe"
    result = check_sys_call(path)
    #pp(result['text'])
    #print(result['num'])