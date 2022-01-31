terraform {
  backend "s3" {
    bucket               = "troydieter.com-tfstate"
    key                  = "event-driven-incoming.tfstate"
    workspace_key_prefix = "event-driven-incoming-tfstate"
    region               = "us-east-1"
    dynamodb_table       = "td-tf-lockstate"
  }
}
