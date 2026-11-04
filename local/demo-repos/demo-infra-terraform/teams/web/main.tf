# Web team stack.

# Order events from the storefront; the fulfilment worker reads them.
module "orders_queue" {
  source         = "../../modules/sqs"
  name           = "web-orders"
  team           = "web"
  retention_days = 7
}

# Product images uploaded by merchandisers (served through CloudFront, never public).
module "product_images" {
  source = "../../modules/s3"
  name   = "web-product-images"
  team   = "web"
}
