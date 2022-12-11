import json
import io
import os
import getpass
from pprint import pprint as pp
import pyhidra
pyhidra.start()
import ghidra
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import VarnodeAST
from ghidra.util.task import ConsoleTaskMonitor



sinks = [
    "getpw",
    "gets",
    "sprintf",
    "strcat",
    "strcpy",
    "vsprinf"
]

def check_buf_ovfw(path):
    result = {}
    text = []
    num = 0

    with pyhidra.open_program(path, project_location=r".\exam",
                              analyze=False) as flat_api:
        print('[+] Checking possibility of buffer overflow....')
        print('--------')
        text.append(str('[+] Checking possibility of buffer overflow....') + '\n')
        text.append(str('--------') + '\n')
        from ghidra.program.util import GhidraProgramUtilities
        program = flat_api.getCurrentProgram()
        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            flat_api.analyzeAll(program)
        fm = program.getFunctionManager()
        functions = [func for func in fm.getFunctions(True)]
        listing = program.getListing()
        monitor = flat_api.getMonitor()

        # addresses = find_danger_func()
        addresses = {}
        count = 0
        # vuln group for json dump
        overflow_vuln_group = dict()

        for function in functions:
            try:
                addresses[function.name].append(function.getEntryPoint())
            except:
                addresses[function.name] = []
                addresses[function.name].append(function.getEntryPoint())

        # ====================================================================
        # 함수 중 sink에 포함되는 함수가 있는지 확인
        function_names = [func.name for func in functions]
        if  (set(sinks) & set(function_names)):
            print("This target contains interesting sink(s). Continuing analysis...")
            text.append("This target contains interesting sink(s). Continuing analysis..." + '\n')
        else:
            print("This target does not contain interesting sink(s). Done.")
            text.append("This target does not contain interesting  sink(s). Done." + '\n')
            result['text'] = text
            result['num'] = num
            return result

        # ====================================================================
        # sink를 call 하는 함수를 가져와서 interesting function에 넣음
        interesting_functions = []
        for func in functions:
            monitor = ConsoleTaskMonitor()
            called_functions = func.getCalledFunctions(monitor)
            called_function_names = [cf.name for cf in called_functions]

            sink_callers = set(called_function_names) & set(sinks)

            if sink_callers:
                interesting_functions.append(func)


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
        #interesting function을 분석
        for func in interesting_functions:
            print("\nAnalyzing function: {}".format(func.name))
            text.append(str("\nAnalyzing function: {}".format(func.name)) + '\n')

            for address in addresses[func.name]:
                references = flat_api.getReferencesTo(address)
                for ref in references:
                    from_addr = ref.getFromAddress()
                    to_addr = ref.getToAddress()
                    from_ins = listing.getInstructionAt(from_addr)
                    to_ins = listing.getInstructionAt(to_addr)
                    if (from_ins is not None) and (to_ins is not None):
                        print('Address: {}'.format(from_addr))
                        text.append(str('Address: {}'.format(from_addr)) + '\n')
                        print('Instruction: {}({})'.format(from_ins.toString(), func.name))
                        text.append(str('Instruction: {}({})'.format(from_ins.toString(), func.name)) + '\n')
                        # dict for json dump
                        vuln = dict()
                        vuln['func_name'] = str(func.name)
                        vuln['address'] = str(from_addr)
                        overflow_vuln_group[count] = vuln
                        count = count + 1
                        num += 1
                        print('--------')
                        text.append('--------' + '\n')


        print("[!] Done! {} possible vulnerabilities found.".format(count))
        text.append(str("[!] Done! {} possible vulnerabilities found.".format(count)) + '\n')

        result['text'] = text
        result['num'] = num
        return result
if __name__ == '__main__':
   result = check_buf_ovfw(r"C:\Users\jjh96\_test.extracted\squashfs-root\lib\librtstream.so")
   pp(result['text'])
   print(result['num'])