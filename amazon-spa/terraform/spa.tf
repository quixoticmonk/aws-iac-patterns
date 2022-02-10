# Variables - please fil these out first

variable "domain_name" {
  type        = string
  default     = "example.com"
  description = "The top level domain to be used"
}

variable "namespace" {
  type        = string
  default     = "example"
  description = "project name"
}

# You will need to proactively create the Route53 forward zone and retrieve this value
variable "parent_zone" {
  type        = string
  default     = "ZXXXX010101010101"
  description = "The Route53 zone ID for the forward zone used with the domain_name value"
}

# CloudFront function used for redirects
module "lambda_at_edge" {
  source = "cloudposse/cloudfront-s3-cdn/aws//modules/lambda@edge"
  name = "spa_index_redirect_${random_id.rando.hex}"
  tags   = local.common-tags

  functions = {
    viewer_request = {
      source = [{
        content  = <<-EOT
          exports.handler = (event, context, callback) => {
            const request = event.Records[0].cf.request;

            if (!/\..+/.test(request.uri)) {
              request.uri = `/index.html`;
            }

            callback(null, request);
          };
        EOT
        filename = "spa_redirect.js"
      }]
      runtime      = "nodejs12.x"
      handler      = "spa_redirect.handler"
      event_type   = "viewer-request"
      include_body = false
    }
  }
}

# Data extracted from existing resources

data "aws_cloudfront_cache_policy" "Managed-CachingOptimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_response_headers_policy" "Managed-SecurityHeadersPolicy" {
  name = "Managed-SecurityHeadersPolicy"
}

module "acm_request_certificate" {
  source = "cloudposse/acm-request-certificate/aws"

  domain_name                       = var.domain_name
  subject_alternative_names         = [var.domain_name, "www.${var.domain_name}", "*.${var.domain_name}"]
  process_domain_validation_options = true
  ttl                               = "300"
}

# Deploy the resources

module "cdn" {
  source                      = "cloudposse/cloudfront-s3-cdn/aws"
  namespace                   = var.namespace
  stage                       = var.environment
  name                        = var.domain_name
  aliases                     = ["www.${var.domain_name}", var.domain_name]
  dns_alias_enabled           = true
  parent_zone_id              = var.parent_zone
  cache_policy_id             = data.aws_cloudfront_cache_policy.Managed-CachingOptimized.id
  response_headers_policy_id  = data.aws_cloudfront_response_headers_policy.Managed-SecurityHeadersPolicy.id
  lambda_function_association = module.lambda_at_edge.lambda_function_association
  tags                        = local.common-tags
  acm_certificate_arn         = module.acm_request_certificate.arn
  depends_on                  = [module.acm_request_certificate]
}