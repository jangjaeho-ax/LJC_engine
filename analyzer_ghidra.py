import pyhidra
import getpass
import os
import collect_CI
from elftools.elf import elffile as elf
import pdb


#ghidra를 이용해 PE 파일 내부의 함수 리스트를 얻는 함수
class analyzer:
    def __init__(self, path):
        self.path = path
        with pyhidra.open_program(path, project_location=r"C:\Users\jjh96\Desktop\reversing\exam",
                                  analyze=False) as flat_api:
            self.program = flat_api.getCurrentProgram()
            self.function_manager = self.program.getFunctionManager()
    def __del__(self):
        print('delete analyzer : {0}'.format(self.path))
    def get_functions(self):
        with pyhidra.open_program(path, project_location=r"C:\Users\jjh96\Desktop\reversing\exam",
                                  analyze=False) as flat_api:
            program = flat_api.getCurrentProgram()
            function_manager = program.getFunctionManager()
            functions = [func for func in function_manager.getFunctions(True)]
            function_names = [func.name for func in functions]
            print(program.getExecutablePath())

            '''
            addresses = {}
            for function in functions:
                try:
                    addresses[function.name].append(function.getEntryPoint())
                except:
                    addresses[function.name] = []
                    addresses[function.name].append(function.getEntryPoint())
            print(addresses)
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
            return function_names
    def run_script(self,script_name):
        script_path = os.getcwd()+'\\ghidra_script\\'+script_name+'.py'
        #print(os.getcwd())
        print(script_path)
        print(self.path)
        pyhidra.run_script(self.path,script_path)
    def get_filepath(self):
        return self.path
    def test(self):
        with pyhidra.open_program(path, project_location=r"C:\Users\jjh96\Desktop\reversing\exam",
                                  analyze=False) as flat_api:
            program = flat_api.getCurrentProgram()
            uid =program.getUniqueProgramID()
            program_context = program.getProgramContext()
            print()
            print('uid : ' + str(uid))
            #print('program_context : ' + program_context)

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
    #a.test()

    #a.get_functions()
    a.run_script('SystemCallChecker_test')
    #test_f = open(path, "rb")
    #e =elf.ELFFile(test_f)
    #print(e.header)