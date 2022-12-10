import pyhidra
import getpass
import os
import cve_inform_checker
from elftools.elf import elffile as elf
import pdb
from ghidra_script import div_zero_checker
from ghidra_script import sys_call_checker
from ghidra_script import buf_overflow_checker


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
            return function_names
    def sys_call_check(self):
        print('analysis {}' .format(self.path))
        SystemCallChecker.check_endl_recall(self.path)


    def buf_ovrf_check(self):
        print('analysis {}'.format(self.path))
        BufferOverflowChecker.check_buf_ovfw(self.path)

    def int_ovrf_check(self):
        print('analysis {}'.format(self.path))
        IntOverflowChecker.check_int_overflow(self.path)

    def get_filepath(self):
        return self.path



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

    #test_f = open(path, "rb")
    #e =elf.ELFFile(test_f)
    #print(e.header)