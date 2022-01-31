# An implementation of event driven architecture using Amazon Lambda, SQS & SNS
The iac code deploys the below resources:
* Amazon Lambda, with an event mapping to SQS
* SNS Topic w/ SQS subscription
* SQS Queue w/ redrive policy
* SQS Queue used for DLQ

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
## Pending