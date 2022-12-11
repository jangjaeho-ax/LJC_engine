import sys
import boto3
from botocore.exceptions import ClientError
import paramiko
import os
import json
from time import sleep
import os, sys
from stat import *
def binwalk(file_path, dir_path):
    result = {}
    text = []
    num = 0

    session = boto3.Session()
    print("session.profile_name", session.profile_name)
    #text.append(str('[+] Checking possibility of buffer overflow....') + '\n')
    ec2_client = session.client('ec2')

    response = ec2_client.describe_instances()

    InstanceDatas = []
    for Reservation in response['Reservations']:
        for Instance in Reservation['Instances']:
            NameTag = next((item for item in Instance['Tags'] if item['Key'] == 'Name'), {}).get('Value', '')
            InstanceDatas.append({
                'NameTag': NameTag,
                'InstanceId': Instance['InstanceId'],

            })

    print('InstanceDatas:', json.dumps(InstanceDatas, indent=4))
    text.append(str(json.dumps(InstanceDatas, indent=4)) + '\n')
    HOST = '3.38.17.109'
    ID = 'ec2-user'
    PASSWD = ''
    key = paramiko.RSAKey.from_private_key_file("TEST.pem")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=HOST, username=ID, pkey=key)
    except:
        print("[!] 에러 : 기기에 연결할 수 없습니다.")
        text.append("[!] 에러 : 기기에 연결할 수 없습니다." + '\n')
        result['text'] = text
        result['num'] = -1
        return result
    sftp = ssh.open_sftp()
    sftp.put(file_path, 'test')
    stdin, stdout, stderr = ssh.exec_command('binwalk -e test')

    for line in stdout.read().splitlines():
        print(line.decode())
    for line in stderr.read().splitlines():
        print(line.decode())
    sleep(6)
    sftp_walk(sftp, '_test.extracted', dir_path, 1, text)
    sftp_walk(sftp, '_test.extracted', dir_path, 2, text)
    sftp.close()
    # stdin, stdout, stderr = ssh.exec_command('rm -rf _test.extracted')
    for line in stdout.read().splitlines():
        print(line.decode())
    for line in stderr.read().splitlines():
        print(line.decode())
    stdin, stdout, stderr = ssh.exec_command('cd /home \n ls')
    stdin.close()
    for line in stdout.read().splitlines():
        print(line.decode())
    for line in stderr.read().splitlines():
        print(line.decode())
    ssh.close()
    result['text'] = text
    result['num'] = 1
    return result


def sftp_walk(sftp, remotepath, localpath, parameter,text):
    files = []
    folders = []

    # Get all directory and file info, recursive mode

    for f in sftp.listdir_attr(remotepath):

        if S_ISDIR(f.st_mode):
            path = linux_path(remotepath, f.filename)
            folders.append(path)
            sftp_walk(sftp, path, localpath, parameter, text)
        else:
            fname = linux_path(remotepath, f.filename)
            files.append(fname)

    if (parameter == 1):
        if folders:
            generate_folder(folders, localpath,text)

    if (parameter == 2):
        if files:
            generate_file(sftp, files, localpath,text)

def generate_folder(foldlist, localpath,text):
    for fold in foldlist:
        path = localpath +'\\'+fold
        mk_path = os.path.abspath(path)

        # Copy internal storage directory tree

        if (os.path.exists(mk_path)):
            pass
        else:
            os.makedirs(mk_path)

    print("[!] Success copy internal storage directory")
    text.append("[!] Success copy internal storage directory" + '\n')

def generate_file(sftp, filelist, localpath,text):
    for file in filelist:
        print(file)
        path = localpath +'\\'+ file
        mk_path = os.path.abspath(path)

        # SFTP get file
        sftp.get(file, mk_path)
        print("[!] Success dump files : " + file)
        text.append("[!] Success dump files : " + file + '\n')
def linux_path(remotepath, filename):
    return str(remotepath) + '/' +str(filename)
if __name__ == "__main__":
    binwalk(r'C:\\Users\\jjh96\\Desktop\\python\\c200_1_082.bin',r'C:\Users\jjh96\Documents')