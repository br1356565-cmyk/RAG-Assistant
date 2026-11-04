variable "name" {
  type        = string
  description = "Queue name: <team>-<purpose>"
}

variable "team" {
  type = string
}

variable "retention_days" {
  type    = number
  default = 4
}

variable "visibility_timeout_seconds" {
  type    = number
  default = 30
}

variable "max_receive_count" {
  type    = number
  default = 5
}

variable "tags" {
  type    = map(string)
  default = {}
}
