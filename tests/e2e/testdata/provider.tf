terraform {
  required_version = ">=1.0"
  required_providers {
    atlassian = {
      source  = "{{NGROK_DOMAIN}}/iacabezasbaculima/sandbox"
      version = ">= 0.1"
    }
  }
}
