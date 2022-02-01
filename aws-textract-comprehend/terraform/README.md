# An implementation of document extraction and analysis using AWS Textract, Amazon Comprehend and Amazon Athena
The iac code deploys the below resources:
* S3 Bucket for analysis and results
* Lambda functions for analysis and processing of files
* SQS Queues to house events
* SNS Topics for notifications

## Deployment steps
1. Create the `provider.tf` file, such as:

        provider "aws" {
        region  = var.aws_region
        profile = var.aws-profile
        }
2. Create the `remote_state.tf` file if utilizing a remote state. More info on this can be found in the official TF documentation.
3. Adjust any tags for the project vanity name in `common-tags-data.tf`.
4. Verify FIFO and other settings in the SQS TF files.
5. Initiliaze and deploy:
        
        terraform init
        terraform apply

## Execution

1. Upload supported file types (`.pdf,.jpg,.pdf`) into the input S3 bucket under input\result-XXXX (rando ID will be generated)
2. Files will be parsed (on object notification) and placed into the root of the directory.

## Pending

* Migrate to latest version of Terraform
* Encrypt all the things
* Improve function code