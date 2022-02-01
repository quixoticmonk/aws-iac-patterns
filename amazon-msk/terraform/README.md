# An implementation of Kafka using Amazon MSK.
The iac code deploys the below resources:
* Amazon VPC (172.16.16.0/20)
* AWS EC2 Instance used as a client
* Amazon MSK Cluster

## Deployment steps
1. Create the `provider.tf` file, such as:

        provider "aws" {
        region  = var.aws_region
        profile = var.aws-profile
        }
2. Create the `remote_state.tf` file if utilizing a remote state. More info on this can be found in the official TF documentation.
3. Adjust any tags for the project vanity name in `common-tags-data.tf`.
4. Verify sizing of the MSK cluster in `variables.tf`. Additional settings found in `data_platform_msk.tf`
5. Verify `msk-client-key-pair.pem` file, which will be used for the SSH keypair to authenticate to the client. It may need to be renamed if you see extra characters in the filename.
6. Initiliaze and deploy:
        
        terraform init
        terraform apply
## Pending
* Event Source Mapping
* Auto Scaling Group for client
* Customization for VPC CIDR and addressing
* Move MSK to module and publish
* Further improved handling of us-east-1e zone (which doesn't support MSK yet)

## Graph
<img src="tf_graph.svg">