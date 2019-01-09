#!/bin/bash

bucketname=sampackages-$(aws sts get-caller-identity | jq -r ".Account")-$(aws configure get region)
aws s3 mb s3://$bucketname
pip install -r src/requirements.txt -t src/
sam package --template-file template.yaml --s3-bucket $bucketname --output-template-file packaged.yaml
sam deploy --template-file packaged.yaml --stack-name Security-Hub-Findings-Demo --capabilities CAPABILITY_IAM
