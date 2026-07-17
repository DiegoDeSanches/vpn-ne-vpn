terraform {
  required_version = "= 1.12.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.58"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.38"
    }
  }

  # Supply bucket, key, region, encryption and locking with -backend-config.
  # Credentials are supplied by workload identity and never written here.
  backend "s3" {}
}
