import sys
import boto3
from botocore.exceptions import ClientError
import paramiko
import os
import json
session =boto3.Session()
print("session.profile_name", session.profile_name)
ec2_client =session.client('ec2')

response =ec2_client.describe_instances()

InstanceDatas = []
for Reservation in response['Reservations']:
    for Instance in Reservation['Instances']:

        NameTag = next((item for item in Instance['Tags'] if item['Key'] == 'Name'),{}).get('Value','')
        InstanceDatas.append({
            'NameTag' : NameTag,
            'InstanceId' : Instance['InstanceId'],

        })

print('InstanceDatas:',json.dumps(InstanceDatas, indent = 4))


HOST= '43.200.182.12'
ID ='ec2-user'
PASSWD =''
key = paramiko.RSAKey.from_private_key_file("TEST.pem")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname= HOST, username= ID, pkey=key)

sftp = ssh.open_sftp()
#sftp.put('C:\\Users\\jjh96\\Desktop\\python\\c200_1_082.bin','test')
sftp.get('_test.extracted','C:\\Users\\jjh96\\Desktop\\python\\_test_extracted')
sftp.close()


stdin, stdout, stderr = ssh.exec_command('cd /home \n ls')

stdin.close()

for line in stdout.read().splitlines():
    print(line.decode())
for line in stderr.read().splitlines():
    print(line.decode())
ssh.close()