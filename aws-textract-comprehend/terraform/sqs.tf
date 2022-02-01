resource "aws_sqs_queue" "ALLEQUEUE" {
  name                       = "queue-${random_id.rando.hex}"
  visibility_timeout_seconds = 240
  kms_master_key_id          = aws_kms_key.sqs_kms_key.id
  tags                       = local.common-tags
}

resource "aws_sqs_queue" "VALIDATEQUEUE" {
  name                       = "queue-validate-${random_id.rando.hex}"
  visibility_timeout_seconds = 240
  kms_master_key_id          = aws_kms_key.sqs_kms_key.id
  tags                       = local.common-tags
}

resource "aws_sqs_queue" "INVALIDATEQUEUE" {
  name              = "queue-invalidate-${random_id.rando.hex}"
  kms_master_key_id = aws_kms_key.sqs_kms_key.id
  tags              = local.common-tags
}