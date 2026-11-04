terraform {
  required_version = ">= 1.6"
}

# Demo only: nothing here is applied.
locals {
  services = ["storefront", "etl"]
}
