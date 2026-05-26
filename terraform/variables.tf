variable "app_name" {
  description = "Name to give the deployed application"
  type        = string
  default     = "opentelemetry-collector"
}

variable "channel" {
  description = "Channel that the charm is deployed from"
  type        = string

  validation {
    condition     = startswith(var.channel, "dev/")
    error_message = "The track of the channel must be 'dev/'. e.g. 'dev/edge'."
  }
}

variable "config" {
  description = "Map of the charm configuration options"
  type        = map(string)
  default     = {}
}

variable "model_uuid" {
  description = "Reference to an existing model resource or data source for the model to deploy to"
  type        = string
}

variable "revision" {
  description = "Revision number of the charm"
  type        = number
  default     = null
}

variable "storage_directives" {
  description = "Map of storage used by the application, which defaults to 1 GB, allocated by Juju"
  type        = map(string)
  default     = {}
}

variable "units" {
  description = "Unit count/scale"
  type        = number
  default     = 1
}
