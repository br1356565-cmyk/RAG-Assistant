variable "name" {
  type        = string
  description = "Bucket name: <team>-<purpose>"
}

variable "team" {
  type        = string
  description = "Owning team id; becomes the team tag"
}

variable "expire_days" {
  type        = number
  default     = null
  description = "Delete objects after this many days (null = keep)"
}

variable "tags" {
  type    = map(string)
  default = {}
}
