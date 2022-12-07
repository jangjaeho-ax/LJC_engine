
import os
import re
import math
from pprint import pprint as pp
def search_vuln(file):
    result = {}
    text = []
    num = 0

    print("search in : " + file)
    text.append(str("search in : " + file)+'\n')
    # pattern = re.compile(r'"([\S])"')
    pattern = re.compile(r'"([^"]*)"')
    pattern2 = re.compile(r'"p([^"]*)d"', re.IGNORECASE)
    pattern3 = re.compile(r'p([^"]*)d', re.IGNORECASE)
    f = open(file, 'r')
    n = 0
    while True:
        n += 1
        line = f.readline()
        if line == '':
            break
        # if ('pwd' in line) or ('password' in line) or ('Pwd' in line) or ('Password' in line):
        if re.search(r'"p([^"]*)d"', line, re.IGNORECASE) is not None:
            pwd = line
            matched_list = re.findall(r'"([^"]*)"', pwd)
            print(line)
            print(matched_list)
            if (len(matched_list) != 0) and (re.match(r'p([^"]*)d', matched_list[0], re.IGNORECASE) is not None):
                ret = calc_complexity(matched_list[-1])
                if ret != 'P':
                    num += 1
                    print('!' * 10 + 'Weak password' + '!' * 10)
                    text.append(str('!' * 10 + 'Weak password' + '!' * 10) + '\n')
                    print('location : ' + str(n) + '\nstr : ' + matched_list[-1] + '\nreason :' + ret)
                    text.append(str('location : ' + str(n) + '\nstr : ' + matched_list[-1] + '\nreason :' + ret) + '\n')
                else:
                    print('*' * 10 + 'Good password' + '*' * 10)
                    text.append(str('*' * 10 + 'Good password' + '*' * 10) + '\n')
                    print('location : ' + str(n) + '\nstr : ' + matched_list[-1] +
                          '\nentropy :' + str(calc_shannon_entropy(matched_list[-1])))
                    text.append(str('location : ' + str(n) + '\nstr : ' + matched_list[-1] +
                          '\nentropy :' + str(calc_shannon_entropy(matched_list[-1]))) + '\n')
            else:
                print('empty list')
                text.append(str('empty list') + '\n')
            # calc_complexity( matched_list[-1])

    f.close()
    result['text'] = text
    result['num'] = num
    return result

def calc_shannon_entropy(string):
    ent = 0.0
    if len(string) < 2:
        return ent
    size = float(len(string))
    for b in range(128):
        freq = string.count(chr(b))
        if freq > 0:
            freq = float(freq) / size
            ent = ent + freq * math.log(freq, 2)
    print(-ent)
    return -ent

def calc_complexity(str):
    if len(str) < 8:
        ret_str = 'Too Short password'
        return ret_str
    elif not re.findall(r'[0-9]+', str):
        ret_str = 'No numeric characters in password'
        return ret_str
    elif not re.findall(r'[a-z]', str):
        ret_str = 'No lowercase characters in password'
        return ret_str
    elif not re.findall(r'[A-Z]',str):
        ret_str = 'No Uppercase characters in password'
        return ret_str
    elif not re.findall('[`~!@#$%^&*(),<.>/?]+', str):
        ret_str = 'No special characters in password'
        return ret_str
    ret_str = 'P'
    return ret_str

def check_password(root_dir):
    result = {}
    text = []
    num = 0
    target_files = []

    if root_dir.strip()[-1] == "\\":
        print(root_dir[:-1])
        text.append(str(root_dir[:-1])+'\n')
    for (root, dirs, files) in os.walk(root_dir):
        print("# root : " + root)
        text.append(str("# root : " + root) + '\n')
        if len(dirs) > 0:
            for dir_name in dirs:
                print("dir: " + dir_name)
                text.append(str("dir: " + dir_name) + '\n')
        if len(files) > 0:
            for file_name in files:
                if (".conf" in file_name) or (".txt" in file_name) or (".json" in file_name):
                    target_files.append(root + '\\' + file_name)
                    # search_vuln(root + '\\' + file_name)
                print("file: " + file_name)
                text.append(str("file: " + file_name) + '\n')
    print('-' * 30)
    text.append(str('-' * 30) + '\n')
    for t in target_files:
        r = search_vuln(t)
        text.append(r['text'])
        num += r['num']

        # print(t)
    result['text'] =text
    result['num'] = num

    return result
if __name__ == "__main__":
    root_dir = "C:\\Users\\jjh96\\_test.extracted\\squashfs-root\\"
    result = check_password(root_dir)
    pp(result['text'])
    print(result['num'])