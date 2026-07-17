data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "fleet" {
  cidr_block           = var.network_cidr
  enable_dns_support   = true
  enable_dns_hostnames = false
  tags                 = { Name = "${var.project}-${var.environment}-aws" }
}

resource "aws_internet_gateway" "fleet" {
  vpc_id = aws_vpc.fleet.id
}

resource "aws_subnet" "public_nat" {
  vpc_id                  = aws_vpc.fleet.id
  cidr_block              = cidrsubnet(var.network_cidr, 8, 0)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.project}-${var.environment}-nat" }
}

resource "aws_subnet" "private" {
  for_each = var.nodes

  vpc_id                  = aws_vpc.fleet.id
  cidr_block              = cidrsubnet(var.network_cidr, 8, each.value.subnet_index)
  availability_zone       = element(data.aws_availability_zones.available.names, each.value.zone_index)
  map_public_ip_on_launch = false
  tags                    = { Name = each.key, Role = each.value.role }

  lifecycle {
    precondition {
      condition     = each.value.zone_index < length(data.aws_availability_zones.available.names)
      error_message = "zone_index must resolve to an available zone without wrapping."
    }
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${var.project}-${var.environment}-nat" }
}

resource "aws_nat_gateway" "fleet" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_nat.id
  depends_on    = [aws_internet_gateway.fleet]
  tags          = { Name = "${var.project}-${var.environment}-nat" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.fleet.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fleet.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public_nat.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.fleet.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.fleet.id
  }
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "node" {
  name                   = "${var.project}-${var.environment}-nodes"
  description            = "No ingress; bounded outbound is additionally filtered by nftables"
  vpc_id                 = aws_vpc.fleet.id
  revoke_rules_on_delete = true
}

resource "aws_vpc_security_group_egress_rule" "tcp" {
  security_group_id = aws_security_group.node.id
  description       = "Tor and explicitly policy-controlled service TCP"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 1
  to_port           = 65535
}

resource "aws_vpc_security_group_egress_rule" "dns" {
  security_group_id = aws_security_group.node.id
  description       = "Approved DNS only; destination is constrained on-host"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
}

resource "aws_vpc_security_group_egress_rule" "ntp" {
  security_group_id = aws_security_group.node.id
  description       = "Approved NTS/NTP bootstrap only; destination is constrained on-host"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "udp"
  from_port         = 123
  to_port           = 123
}

data "aws_iam_policy_document" "assume_instance" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  for_each           = var.nodes
  name               = substr("${var.project}-${var.environment}-${each.key}", 0, 64)
  assume_role_policy = data.aws_iam_policy_document.assume_instance.json
  description        = "Identity-only role for Vault AWS auth: ${each.value.role}"
  tags               = { Role = each.value.role, SecretScope = each.value.secret_scope }
}

resource "aws_iam_instance_profile" "node" {
  for_each = var.nodes
  name     = aws_iam_role.node[each.key].name
  role     = aws_iam_role.node[each.key].name
}

resource "aws_kms_key" "node_disk" {
  for_each                = var.nodes
  description             = "Independent disk key for ${each.key}; not an application signing key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = { Role = each.value.role, Node = each.key }
}

resource "aws_kms_alias" "node_disk" {
  for_each      = var.nodes
  name          = "alias/${var.project}/${var.environment}/${each.key}/disk"
  target_key_id = aws_kms_key.node_disk[each.key].key_id
}

resource "aws_instance" "node" {
  for_each = var.nodes

  ami                         = each.value.image_id
  instance_type               = each.value.instance_type
  availability_zone           = aws_subnet.private[each.key].availability_zone
  subnet_id                   = aws_subnet.private[each.key].id
  vpc_security_group_ids      = [aws_security_group.node.id]
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.node[each.key].name
  source_dest_check           = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.node_disk[each.key].arn
    volume_type = "gp3"
    volume_size = 16
  }

  # This is deliberately non-secret. Cloud user-data is visible in state/provider APIs.
  user_data = <<-NODE_ENV
    ONIONROUTE_NODE_ID=${each.key}
    ONIONROUTE_ROLE=${each.value.role}
    ONIONROUTE_CLOUD=aws
    ONIONROUTE_VAULT_ADDR=${var.vault_addr}
    ONIONROUTE_VAULT_AUTH_ROLE=${each.value.vault_auth_role}
    ONIONROUTE_SECRET_SCOPE=${each.value.secret_scope}
    ONIONROUTE_RELEASE_DIGEST=${each.value.release_digest}
    ONIONROUTE_RELEASE_PUBLIC_KEY=${var.release_signing_public_key}
  NODE_ENV

  user_data_replace_on_change = true

  tags = {
    Name                  = each.key
    Role                  = each.value.role
    ASN                   = tostring(each.value.asn)
    AdminDomain           = each.value.admin_domain
    ManagementTrustDomain = each.value.management_trust_domain
    ReleaseDigest         = each.value.release_digest
  }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = can(regex("^ami-[0-9a-fA-F]{8,17}$", each.value.image_id))
      error_message = "AWS image_id must be a pinned AMI ID, never a moving name/filter."
    }
  }
}
