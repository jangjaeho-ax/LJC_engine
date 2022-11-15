import pyhidra
import os
import collect_CI
from elftools.elf import elffile as elf
import pdb


#ghidra를 이용해 PE 파일 내부의 함수 리스트를 얻는 함수
class analyzer:
    def __init__(self, path):
        self.path = path

    def get_functions(self):
        with pyhidra.open_program(path, project_location=r"C:\Users\jjh96\Desktop\reversing\exam",
                                  analyze=False) as flat_api:
            program = flat_api.getCurrentProgram()
            function_manager = program.getFunctionManager()
            functions = [func for func in function_manager.getFunctions(True)]
            function_names = [func.name for func in functions]
            addresses = {}
            for function in functions:
                try:
                    addresses[function.name].append(function.getEntryPoint())
                except:
                    addresses[function.name] = []
                    addresses[function.name].append(function.getEntryPoint())
            print(addresses)
            '''
            funtion_iter = function_manager.getFunctions(True)
            done_looping = False
            while not done_looping:
                try:
                    item = next(funtion_iter)
                except StopIteration:
                    done_looping = True
                else:
                    print(item)
            '''
    def run_script(self,script_name):
        script_path = r'/ghidra/'+script_name+'.py'
        pyhidra.run_script(self.path,script_path)
    def get_filename(self):
        return

'''
def get_functions(path):
    with pyhidra.open_program(path, project_location="C:/Users/jjh96/Desktop/reversing/exam", analyze=False ) as flat_api:
        program = flat_api.getCurrentProgram()
        #listing = program.getListing()
        #print(listing.getCodeUnitAt(flat_api.toAddr(0x1234)))

        function_manager = program.getFunctionManager()
        funtion_iter = function_manager.getFunctions(True)
        done_looping = False
        while not done_looping:
            try:
                item = next(funtion_iter)
            except StopIteration:
                done_looping = True
            else:
                print(item)

        # 무시해도 괜찮은 오류표시
        from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
        decomp_api = FlatDecompilerAPI(flat_api)
        # ...
        decomp_api.dispose()
'''

if __name__ == "__main__":
    path = r"C:\Users\jjh96\_test.extracted\squashfs-root\lib\librtstream.so"
    root_dir =r"C:\Users\jjh96\_test.extracted\squashfs-root\lib"
    a = analyzer(path)
    a.get_functions()
    a.run_script('SystemCallChecker')
    #test_f = open(path, "rb")
    #e =elf.ELFFile(test_f)
    #print(e.header)