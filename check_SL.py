import pyhidra
import os
import collect_CI
def bin_to_ghidra(path):
    with pyhidra.open_program(path, project_location=r"C:\Users\jjh96\Desktop\reversing\exam") as flat_api:
        program = flat_api.getCurrentProgram()
        listing = program.getListing()
        print(listing.getCodeUnitAt(flat_api.toAddr(0x1234)))

        # We are also free to import ghidra while in this context to do more advanced things.
        from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
        decomp_api = FlatDecompilerAPI(flat_api)
        # ...
        decomp_api.dispose()
def get_so_name(root_dir):
    target_files = {}
    if root_dir.strip()[-1] == "\\":
        print(root_dir[:-1])
    for (root, dirs, files) in os.walk(root_dir):
        print("# root : " + root)
        if len(dirs) > 0:
            for dir_name in dirs:
                print("dir: " + dir_name)
        if len(files) > 0:
            #가장 첫 파일 이름으로 초기화
            prior_file = ""
            for file_name in files:
                #.so 파일을 대상으로
                if (".so" in file_name):
                    if prior_file == "":
                        prior_file = file_name
                    #이전 파일 명이 파일 명에 포함되어 있지 않는 경우
                    if prior_file not in file_name:
                        #타켓 파일에 이전파일을 추가
                        #target_files.append(root + '\\' + prior_file)

                        target_files[prior_file] = root
                    #해당 파일명이 이전파일 명이 된다.
                    prior_file = file_name
                    # search_vuln(root + '\\' + file_name)
                print("file: " + file_name)
            #마지막으로 이전 파일을 넣는다.
            #target_files.append(root + '\\' + prior_file)
            target_files[prior_file] = root
    print('-' * 30)
    return target_files
if __name__ == "__main__":
    path = r"C:\Users\jjh96\_test.extracted\squashfs-root\lib\librtstream.so"
    root_dir =r"C:\Users\jjh96\_test.extracted\squashfs-root\lib"
    #cve =CVESearch('https://cve.circl.lu')
    #result = cve.cpe22('cpe:/a:libavformat_project:libavformat:57.34.103')
    #print(result.text)
    target_files = get_so_name(root_dir)
    print(target_files)
    for k in target_files.keys():
        i = k.find('.so')
        #print(k[0:i])
        collect_CI.search_cpe22(k[0:i])
        #collect_CI.search_cve(k[0:i])
