variable "environmentPrefix" {
    type = string  
}

variable "instanceType" {
    type = string  
}

variable "imageId" {
    type = string  
}

variable "vpcCIDRBlock" {
    type = string  
}

variable "vSwitchCIDRBlock" {
    type = string  
}

variable "sshIPWhitelist" {
    type = string  
}

variable "tags" {
    type = object({
        environment = string
        purpose     = string
        builtby     = string
  })
}