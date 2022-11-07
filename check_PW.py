import nvdlib
import os
import re
import math
def search_vuln(file):
   print("search in : " + file)
   #pattern = re.compile(r'"([\S])"')
   pattern = re.compile(r'"([^"]*)"')
   pattern2 = re.compile(r'"p([^"]*)d"', re.IGNORECASE)
   pattern3 = re.compile(r'p([^"]*)d', re.IGNORECASE)
   f = open(file, 'r')
   n = 0
   while True:
       n+=1
       line = f.readline()
       if line == '':
           break
       #if ('pwd' in line) or ('password' in line) or ('Pwd' in line) or ('Password' in line):
       if re.search(r'"p([^"]*)d"',line, re.IGNORECASE) is not None :
           pwd  = line
           matched_list = re.findall(r'"([^"]*)"', pwd)
           print(line)
           print(matched_list)
           if (len(matched_list) != 0 ) and (re.match(r'p([^"]*)d',matched_list[0],re.IGNORECASE) is not None):
               ret = calc_complexity(matched_list[-1])
               if ret != 'P':
                   print('!'*10 + 'Weak password' + '!'*10)
                   print('location : ' + str(n) + '\nstr : ' + matched_list[-1] + '\nreason :' + ret)
               else:
                   print('*'*10 + 'Good password' + '*'*10)
                   print('location : ' + str(n) + '\nstr : ' + matched_list[-1] +
                         '\nentropy :' + str(calc_shannon_entropy(str)))
           else:
               print('empty list')
           #calc_complexity( matched_list[-1])

   f.close()

def calc_shannon_entropy(string):
    """
    Calculates the Shannon entropy for the given string.

    :param string: String to parse.
    :type string: str

    :returns: Shannon entropy (min bits per byte-character).
    :rtype: float
    """
    """
    if isinstance(string, unicode):
        string = string.encode("ascii")
    """

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
'''
def calc_complexity(str, reason=None):
    if len(str) < 8 and not re.findall(r'[0-9]+', str) and not re.findall(r'[a-z]', str) or not re.findall(r'[A-Z]', str):
        return False
    elif not re.findall('[`~!@#$%^&*(),<.>/?]+', str) :
        return False
    return True
'''
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
    target_files = []
    if root_dir.strip()[-1] == "\\":
        print(root_dir[:-1])
    for (root, dirs, files) in os.walk(root_dir):
        print("# root : " + root)
        if len(dirs) > 0:
            for dir_name in dirs:
                print("dir: " + dir_name)
        if len(files) > 0:
            for file_name in files:
                if (".conf" in file_name) or (".txt" in file_name) or (".json" in file_name):
                    target_files.append(root + '\\' + file_name)
                    # search_vuln(root + '\\' + file_name)
                print("file: " + file_name)
    print('-' * 30)
    for t in target_files:
        search_vuln(t)
        # print(t)
if __name__ == "__main__":
    root_dir = "C:\\Users\\jjh96\\_test.extracted\\squashfs-root\\"
    check_password(root_dir)