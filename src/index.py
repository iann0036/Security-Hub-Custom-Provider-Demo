import boto3
import requests
import json
import hashlib
import os
from dateutil import parser
import time

securityhub = boto3.client('securityhub')
     
def handler(event, context):
    email_addresses = [
        "test@example.com",
        "something@example.com"
    ]

    for email_address in email_addresses:
        try:
            entries = json.loads(requests.get("https://haveibeenpwned.com/api/v2/breachedaccount/{}".format(email_address)).text)

            findings = []
            for entry in entries:
                finding_id = hashlib.md5(email_address.encode() + entry['Name'].encode()).hexdigest()
                finding_types = []
                for finding_type in entry['DataClasses']:
                    finding_types.append('Sensitive Data Identifications/PII/{}'.format(finding_type))

                findings.append({
                    'SchemaVersion': '2018-10-08',
                    'Id': finding_id,
                    'ProductArn': 'arn:aws:securityhub:{}:{}:product/{}/default'.format(os.environ['REGION'], os.environ['ACCOUNTID'], os.environ['ACCOUNTID']),
                    'GeneratorId': 'haveibeenpwned-detector',
                    'AwsAccountId': os.environ['ACCOUNTID'],
                    'Types': finding_types,
                    'FirstObservedAt': parser.parse(entry['BreachDate']).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'LastObservedAt': parser.parse(entry['BreachDate']).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'CreatedAt': parser.parse(entry['AddedDate']).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'UpdatedAt': parser.parse(entry['ModifiedDate']).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    'Severity': {
                        'Product': 10.0 if entry['IsSensitive'] else 5.0,
                        'Normalized': 100 if entry['IsSensitive'] else 50
                    },
                    'Confidence': 100 if entry['IsVerified'] else 80,
                    'Criticality': 100,
                    'Title': "Account Compromise - {}".format(entry['Title']),
                    'Description': (entry['Description'][:1020] + '...') if len(entry['Description']) > 1023 else entry['Description'],
                    'ProductFields': {
                        'Domain': entry['Domain'],
                        'IsFabricated': str(entry['IsFabricated']),
                        'IsRetired': str(entry['IsRetired']),
                        'IsSensitive': str(entry['IsSensitive']),
                        'IsSpamList': str(entry['IsSpamList']),
                        'IsVerified': str(entry['IsVerified']),
                        'LogoPath': str(entry['LogoPath']),
                        'PwnCount': str(entry['PwnCount'])
                    },
                    'Resources': [
                        {
                            'Id': email_address,
                            'Type': 'Email Address'
                        }
                    ]
                })

            if len(findings) > 0:
                response = securityhub.batch_import_findings(
                    Findings=findings
                )
                if response['FailedCount'] > 0:
                    print("Failed to import {} findings".format(response['FailedCount']))
        except:
            print("Skipping {}".format(email_address))

        time.sleep(1.6) # Rate limit for HaveIBeenPwned
