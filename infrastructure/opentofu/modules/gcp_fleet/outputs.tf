output "inventory" {
  value = {
    for name, node in google_compute_instance.node : name => {
      provider    = "gcp"
      role        = var.nodes[name].role
      instance_id = node.instance_id
      private_ip  = node.network_interface[0].network_ip
      image_id    = var.nodes[name].image_id
    }
  }
}

output "workload_identities" {
  value = { for name, account in google_service_account.node : name => account.email }
}

