# State lives in S3. Supply the settings at init:
#   terraform init -backend-config=backend.hcl
# See backend.hcl.example.
terraform {
  backend "s3" {}
}
