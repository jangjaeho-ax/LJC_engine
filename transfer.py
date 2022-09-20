import json
import sys
import boto3
from botocore.exceptions import ClientError
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