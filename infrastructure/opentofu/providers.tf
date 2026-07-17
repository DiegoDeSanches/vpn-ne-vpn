provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "opentofu"
      DataClass   = "no-user-data"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

