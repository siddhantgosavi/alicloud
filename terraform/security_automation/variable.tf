variable "environmentPrefix" {
    type = string  
}

variable "vpcCIDRBlock" {
    type = string  
}

variable "vSwitchCIDRBlock" {
    type = string  
}

variable "bucketName" {
    type = string  
}

variable "tags" {
    type = object({
        environment = string
        purpose     = string
  })
}