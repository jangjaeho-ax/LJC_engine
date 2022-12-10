
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
#CWE-674 패턴을 검출
sinks = [
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

def check_endl_recall(path):
    result = {}
    text = []
    num = 0

    with pyhidra.open_program(path, project_location=r"C:\Users\jjh96\Desktop\reversing\exam",
                              analyze=False) as flat_api:
        print('[+] Checking possibility of endless recursive call....')
        print('--------')
        text.append(str('[+] Checking possibility of endless recursive call....') + '\n')
        program = flat_api.getCurrentProgram()
        #flat_api.analyzeAll(program)
        fm = program.getFunctionManager()
        functions = [func for func in fm.getFunctions(True)]

        # store all entry points of function
        addresses = {}
        count = 0
        for function in functions:
            try:
                addresses[function.name].append(function.getEntryPoint())
            except:
                addresses[function.name] = []
                addresses[function.name].append(function.getEntryPoint())

        print(functions)
        # ===========================================   =========================
        # Recursive call을 하는 함수를 interesting function에 넣음
        interesting_functions = []
        for func in functions:
            #print('{0} : {1}'.format(func, func.name))
            #if func.name == r'_Z22do_something_recursivei':
                #print(func.name)
            monitor = ConsoleTaskMonitor()
            called_functions = func.getCalledFunctions(monitor)
            called_function_names = [cf.name for cf in called_functions]

            if func.name in called_function_names:
                print(func.name)
                interesting_functions.append(func)
        if len(interesting_functions) <= 0:
            print("\nNo interesting functions found to analyze. Done.")
            text.append("\nNo interesting functions found to analyze. Done." + '\n')
            result['text'] = text
            result['num'] = num
            return result
        else:
            print("\nFound {} interesting functions to analyze:".format(len(interesting_functions)))
            text.append(str("\nFound {} interesting functions to analyze:".format(len(interesting_functions)))+ '\n')
            for func in interesting_functions:
                print("  {}".format(func.name))
                text.append(str("  {}".format(func.name)) + '\n')


        # ====================================================================
        # interesting function을 분석
        for func in interesting_functions:
            print("\nAnalyzing function: {}".format(func.name))
            text.append(str("\nAnalyzing function: {}".format(func.name)) + '\n')
            local_variables = func.getAllVariables()
            print(local_variables)
            print('\n\n')
            call_args = []
            sinks_args = []
            interesting_args = []
            # 함수를 디컴파일 해서 pcode를 가져올수 있게 만듬
            hf = get_high_function(func, program)
            opiter = hf.getPcodeOps()
            while opiter.hasNext():
                op = opiter.next()
                mnemonic = op.getMnemonic()
                #print(op)
                if mnemonic == "CALL":
                    opinputs = op.getInputs()
                    call_target = opinputs[0]
                    call_target_addr = call_target.getAddress()
                    call_target_name = fm.getFunctionAt(call_target_addr).getName()
                    if call_target_name ==func.name:
                        call_args = opinputs
                        #print('\n\n')
                        #print(op)
                        #print('\n\n')
                elif mnemonic in sinks:
                    sinks_args = op.getInputs()
            for s in call_args:
                if s in sinks_args:
                    interesting_args.append(s)
            if interesting_args is None:
                print("  Function {} is Safe".format(func.name))
                text.append(
                    str("  Function {} is Safe".format(func.name)) + '\n')
                result['text'] = text
                result['num'] = num
                return result
            flag = True
            while opiter.hasNext():
                op = opiter.next()
                mnemonic = op.getMnemonic()
                opinputs = op.getInputs()
                if len(opinputs) >= 3:
                    output_arg = opinputs[2]
                    if output_arg in interesting_args:
                        #print(op)
                        flag = False
            if flag is False:
                print("  Function {} is Safe".format(func.name))
                text.append(
                    str("  Function {} is Safe".format(func.name)) + '\n')
            else:
                num += 1
                print(
                    "  [!] Alert: Function {} appears to contain a 'Endless Recursive call' pattern!".format(func.name))
                text.append(
                    str("  [!] Alert: Function {} appears to contain a 'Endless Recursive call' pattern!".format(
                        func.name)) + '\n')




        result['text'] = text
        result['num'] = num
        return result

if __name__ == "__main__":
    path = r"C:\Users\jjh96\Desktop\reversing\test\endless.exe"
    result = check_endl_recall(path)
    pp(result['text'])
    print(result['num'])