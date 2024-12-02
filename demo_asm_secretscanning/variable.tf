##############################################
## Credentials #
##############################################

variable "access_key" {
  type    = string
  default = "AKIA25VHUDYUG7Y6CV4W"
}

variable "secret_key" {
  type    = string
  default = "HakUYBCmrjS81xgWxUOZaaxVq8AGivHEnFBjNEOJ"
}

variable "key_name" {
  type    = string
  default = "<enter key name here>"
}
variable "public_key" {
  type    = string
  default = "<enter public key string here>"
}

##############################################
## VPC related #
##############################################

# VPC variables
variable "demo_secret_scanning_vpc" {
  type        = string
  description = "CIDR for demo_secret_scanning VPC"
  default     = "192.168.10.0/24"
}

# Subnet variables
variable "demo_secret_scanning_subnet" {
  type        = string
  description = "CIDR for demo_secret_scanning subnet"
  default     = "192.168.10.0/24"
}


##############################################
## EC2 instances #
##############################################

variable "demo_secret_scanning_ami" {
  type        = string
  description = "AMI instance"
  default     = "ami-0bc64185df5784cc3" #Win Server 2019 Base
}

variable "demo_secret_scanning_instance" {
  type        = string
  description = "EC2 instance size"
  default     = "t3.large"
}

variable "root_volume_size" {
  description = "Size (in Gb) of EBS volume"
  default     = 60
}