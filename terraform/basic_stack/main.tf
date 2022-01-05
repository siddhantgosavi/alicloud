
# Configure the Alicloud Provider

# Run the following commands before running init

# export ALICLOUD_ACCESS_KEY="anaccesskey"
# export ALICLOUD_SECRET_KEY="asecretkey"
# export ALICLOUD_REGION="cn-beijing"

provider "alicloud" {
    
}

resource "alicloud_vpc" "vpc" {
  vpc_name   = "${var.environmentPrefix}-vpc"
  cidr_block = var.vpcCIDRBlock
  tags = var.tags
}

data "alicloud_zones" "default" {
}

resource "alicloud_vswitch" "vswitch" {
  vswitch_name      = "${var.environmentPrefix}-subnet"
  vpc_id            = alicloud_vpc.vpc.id
  cidr_block        = var.vSwitchCIDRBlock
  zone_id           = data.alicloud_zones.default.zones[0].id
  tags = var.tags

  depends_on = [alicloud_vpc.vpc]
}

# resource "alicloud_route_table" "routetable" {
#   vpc_id           = alicloud_vpc.vpc.id
#   route_table_name = "${var.environmentPrefix}-rt"
#   tags = var.tags
# }

resource "alicloud_security_group" "group" {
  name   = "${var.environmentPrefix}-sg"
  vpc_id = alicloud_vpc.vpc.id
  tags = var.tags
}

resource "alicloud_security_group_rule" "allow_ssh_tcp" {
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "intranet"
  policy            = "accept"
  port_range        = "22/22"
  priority          = 1
  security_group_id = alicloud_security_group.group.id
  cidr_ip           = var.sshIPWhitelist
}

resource "alicloud_instance" "ecs_instance" {
  image_id          = var.imageId
  instance_type     = var.instanceType
  availability_zone = data.alicloud_zones.default.zones[0].id
  security_groups   = [alicloud_security_group.group.id]
  vswitch_id        = alicloud_vswitch.vswitch.id
  instance_name     = "${var.environmentPrefix}-instance"
  tags = var.tags
}

resource "alicloud_eip_address" "eip" {
  address_name         = "${var.environmentPrefix}-eip"
}

resource "alicloud_eip_association" "eip_asso" {
  allocation_id = alicloud_eip_address.eip.id
  instance_id   = alicloud_instance.ecs_instance.id
}

