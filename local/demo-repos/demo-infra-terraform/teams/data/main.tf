# Data team stack.

# Nightly exports for analysts; kept 30 days.
module "exports" {
  source      = "../../modules/s3"
  name        = "data-exports"
  team        = "data"
  expire_days = 30
}
