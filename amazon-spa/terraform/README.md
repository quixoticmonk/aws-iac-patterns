# An implementation of a SPA (Single Page Application)
The iac code deploys the below resources:
* Amazon CloudFront distribution
* Amazon CloudFront security policy associated with the distribution (security headers)
* Amazon CloudFront caching policy associated with SPA's
* Amazon CloudFront OAI (Origin Access Identity) used to route traffic exclusively from the CloudFront distribution to the Amazon S3 bucket
* Amazon S3 bucket for static site placement (place your static site contents here)

## Deployment steps
1. Create an Amazon Route53 forward zone with your domain name (example.com)
2. Use those NameServer values and set your domain registrar to point to it
3. Adjust the `parent_zone` variable in the `main.tf` file to reflect the Amazon Route53 ID (should be like `Z856486485646`)
4. Create the `remote_state.tf` file if utilizing a remote state. More info on this can be found in the official TF documentation.
5. Adjust any tags for the project vanity name in `common-tags-data.tf`.
6. Verify FIFO and other settings in the SQS TF files.
7. Initiliaze and deploy:
        
        terraform init
        terraform apply

## Pending
* Add in `Lambda@Edge` functions if needed, for index page redirects
* Move to complete solution: add in CodePipeline + CodeBuild for Gatsby\Hugo builds