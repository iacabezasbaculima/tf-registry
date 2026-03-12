terraform {
  required_version = ">=1.0"
}

# Public Terraform module
module "public_module" {
  source  = "{{NGROK_DOMAIN}}/terraform-aws-modules/terraform-aws-ecr/aws"
  version = "3.2.0"
}

# Private Terraform module
module "private_module" {
  source  = "{{NGROK_DOMAIN}}/iacabezasbaculima/terraform-aws-iam/aws"
  version = "6.4.0"
}
