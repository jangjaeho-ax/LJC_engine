# Check Buffer Overflow
# @author: tkmru
# @category: LazyGhidra
# potentially vulnerable functions

import json
from ghidra.program.model.listing import CodeUnit

sinks = [
    "getpw",
    "gets",
    "sprintf",
    "strcat",
    "strcpy",
    "vsprinf"
]


def add_bookmark_comment(address, category, description):
    cu = currentProgram.getListing().getCodeUnitAt(address)
    createBookmark(address, category, description)
    cu.setComment(CodeUnit.EOL_COMMENT, description)


def find_danger_func():

    addresses = {}
    function = getFirstFunction()
    while function is not None:
        if monitor.isCancelled():
            return doCancel()

        if function.name in sinks:
            try:
                addresses[function.name].append(function.getEntryPoint())
            except:
                addresses[function.name] = []
                addresses[function.name].append(function.getEntryPoint())

        function = getFunctionAfter(function)

    return addresses
def main():
    print('[+] Checking possibility of buffer overflow....')
    print('--------')
    listing = currentProgram.getListing()
    addresses = find_danger_func()
    count = 0
    # vuln group for json dump
    overflow_vuln_group = dict()

    for func_name in addresses:
        for address in addresses[func_name]:
            references = getReferencesTo(address)
            for ref in references:
                from_addr = ref.getFromAddress()
                to_addr = ref.getToAddress()
                from_ins = listing.getInstructionAt(from_addr)
                to_ins = listing.getInstructionAt(to_addr)
                if (from_ins is not None) and (to_ins is not None):
                    print('Address: {}'.format(from_addr))
                    print('Instruction: {}({})'.format(from_ins.toString(), func_name))
                    add_bookmark_comment(from_addr, 'Possibility of buffer overflow', func_name + ' is unsafe...')
                    # dict for json dump
                    vuln = dict()
                    vuln['func_name'] = func_name
                    vuln['address'] = from_addr
                    overflow_vuln_group[count] = vuln
                    count = count + 1
                    print('--------')

    print("[!] Done! {} possible vulnerabilities found.".format(count))
    print(overflow_vuln_group)

if __name__ == '__main__':
   main()