aws cloudformation create-stack \
  --stack-name cloud-hun-lab \
  --template-body file://lab/vuln-lab.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --region eu-west-1

