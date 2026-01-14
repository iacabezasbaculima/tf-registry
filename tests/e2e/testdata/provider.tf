terraform {
  required_version = ">=1.0"
  required_providers {
    atlassian = {
      source  = "{{NGROK_DOMAIN}}/openscientia/sandbox"
      version = ">= 0.1"
    }
  }
}
