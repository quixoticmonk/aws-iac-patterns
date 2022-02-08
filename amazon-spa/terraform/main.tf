# Variables - please fil these out first

variable "domain_name" {
  type = string
  default = "example.com"
  description = "The top level domain to be used"
}

# You will need to proactively create the Route53 forward zone and retrieve this value
variable "parent_zone" {
  type = string
  default = "ZXXXX010101010101"
  description = "The Route53 zone ID for the forward zone used with the domain_name value"
}

variable "stage" {
  type = string
  default = "dev"
  description = "The level of environment - such as dev, test, live-preview, prod"
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
  source = "cloudposse/cloudfront-s3-cdn/aws"
  namespace                  = "example"
  stage                      = var.stage
  name                       = var.domain_name
  aliases                    = ["www.${var.domain_name}", var.domain_name]
  dns_alias_enabled          = true
  parent_zone_id             = var.parent_zone
  cache_policy_id            = data.aws_cloudfront_cache_policy.Managed-CachingOptimized.id
  response_headers_policy_id = data.aws_cloudfront_response_headers_policy.Managed-SecurityHeadersPolicy.id

  acm_certificate_arn = module.acm_request_certificate.arn
  depends_on          = [module.acm_request_certificate]
}