
# Configure the Alicloud Provider

# Run the following commands before running 'terraform init --backend-config dev/backend.config'

# export ALICLOUD_ACCESS_KEY="anaccesskey"
# export ALICLOUD_SECRET_KEY="asecretkey"
# export ALICLOUD_REGION="cn-beijing"

provider "alicloud" {
    
}

resource "alicloud_vpc" "vpc" {
  vpc_name   = "${var.environmentPrefix}-secauto-vpc"
  cidr_block = var.vpcCIDRBlock
  tags = var.tags
}

data "alicloud_zones" "default" {
}

resource "alicloud_vswitch" "vswitch" {
  vswitch_name      = "${var.environmentPrefix}-secauto-fc-subnet"
  vpc_id            = alicloud_vpc.vpc.id
  cidr_block        = var.vSwitchCIDRBlock
  zone_id           = data.alicloud_zones.default.zones[0].id
  tags = var.tags

  depends_on = [alicloud_vpc.vpc]
}

resource "alicloud_security_group" "group" {
  name   = "${var.environmentPrefix}-secauto-sg"
  vpc_id = alicloud_vpc.vpc.id
  tags = var.tags
}

# resource "alicloud_security_group_rule" "allow_ssh_tcp" {
#   type              = "ingress"
#   ip_protocol       = "tcp"
#   nic_type          = "intranet"
#   policy            = "accept"
#   port_range        = "22/22"
#   priority          = 1
#   security_group_id = alicloud_security_group.group.id
#   cidr_ip           = var.sshIPWhitelist
# }

data "alicloud_nas_zones" "default" {
  file_system_type = "standard"
}

resource "alicloud_nas_file_system" "nasfileshare" {
  file_system_type = "standard"
  protocol_type    = "NFS"
  storage_type     = "Capacity"
  description      = "${var.environmentPrefix}-secauto-storage"
  capacity         = 100
}

resource "alicloud_nas_access_group" "naspermissiongroup" {
  access_group_name = "${var.environmentPrefix}-secauto-storage-Group"
  access_group_type = "Vpc"
  description       = "${var.environmentPrefix}-secauto-storage-Group"
  file_system_type  = "standard"
}

resource "alicloud_nas_access_rule" "naspermissiongrouprule" {
  access_group_name = alicloud_nas_access_group.naspermissiongroup.access_group_name
  source_cidr_ip    = "0.0.0.0/0"
  rw_access_type    = "RDWR"
  user_access_type  = "no_squash"
  priority          = 100
}

resource "alicloud_nas_mount_target" "nasmounttarget" {
  file_system_id    = alicloud_nas_file_system.nasfileshare.id
  access_group_name = alicloud_nas_access_group.naspermissiongroup.access_group_name
  vswitch_id = alicloud_vswitch.vswitch.id
  security_group_id = alicloud_security_group.group.id
}

resource "alicloud_oss_bucket" "report-bucket" {
  bucket = var.bucketName
  acl    = "private"
}

resource "alicloud_log_project" "fclogproject" {
  name        = "${var.environmentPrefix}-security-automation-log-project"
  description = "tf unit test"
}

resource "alicloud_log_store" "fclogstore" {
  project          = alicloud_log_project.fclogproject.name
  name             = "security-automation-log-store"
  retention_period = "3000"
  shard_count      = 1
}

resource "alicloud_fc_service" "securityautomation-fc-service" {
  name        = "${var.environmentPrefix}-SecurityAutomation"
  description = "${var.environmentPrefix}-SecurityAutomation"
  log_config {
    project  = alicloud_log_project.fclogproject.name
    logstore = alicloud_log_store.fclogstore.name
  }
  #role       = alicloud_ram_role.default.arn
  #depends_on = [alicloud_ram_role_policy_attachment.default]
}