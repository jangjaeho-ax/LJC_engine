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


HOST= '172.31.35.246'
ID ='ec2-user'
PASSWD =''
key = paramiko.RSAKey.from_private_key_file("TEST.pem")
ssh= paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname= HOST, username= ID, pkey=key)

sftp = ssh.open_sftp()
sftp.put('C:\\Users\\jjh96\\Desktop\\python\\ringax_ml_14_160.bin','home')
sftp.get('/home/ec2-user','C:\\Users\\jjh96\\Desktop\\python\\ringax_ml_14_161.bin')

sftp.close()


stdin, stdout, stderr = ssh.exec_command('cd /home \n ls')

stdin.close()

for line in stdout.read().splitlines():
    print(line.decode())
for line in stderr.read().splitlines():
    print(line.decode())
ssh.close()