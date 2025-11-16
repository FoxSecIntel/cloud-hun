
## Validaiton
```
cd ~/cloud-hun

aws cloudformation validate-template \
  --template-body file://lab/vuln-lab.yml \
  --region eu-west-1
```
## Creation
```
aws cloudformation create-stack \
  --stack-name cloud-hun-lab \
  --template-body lab/vuln-lab.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --region eu-west-1
```

