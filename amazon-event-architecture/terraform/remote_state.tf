terraform {
  backend "s3" {
    bucket               = "troydieter.com-tfstate"
    key                  = "events.tfstate"
    workspace_key_prefix = "events-tfstate"
    region               = "us-east-1"
    dynamodb_table       = "td-tf-lockstate"
  }
}
