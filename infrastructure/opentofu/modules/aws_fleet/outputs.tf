output "inventory" {
  value = {
    for name, node in aws_instance.node : name => {
      provider    = "aws"
      role        = var.nodes[name].role
      instance_id = node.id
      private_ip  = node.private_ip
      image_id    = node.ami
    }
  }
}

output "workload_identities" {
  value = { for name, role in aws_iam_role.node : name => role.arn }
}

