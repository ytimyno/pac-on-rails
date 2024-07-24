resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
  tags = {
    "Environment" = "Anything"
  }
}

resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    tags = {
      Environment = "default_node_pool.env"
      Owner = "default_node_pool.own"
    }
    node_labels = {
      "dom2ain.key" = "my k8s label azure node_pool"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Owner = "own"
    Environment = "own"
  }
  
}

output "client_certificate" {
  value     = azurerm_kubernetes_cluster.example.kube_config[0].client_certificate
  sensitive = true
}

output "kube_config" {
  value = azurerm_kubernetes_cluster.example.kube_config_raw

  sensitive = true
}
