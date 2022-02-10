locals {
  common-tags = {
    "project"     = "aws-iac-patterns"
    "environment" = var.environment
    "id"          = random_id.rando.hex
  }
}

data "aws_caller_identity" "current" {}

resource "random_id" "rando" {
  byte_length = 2
}