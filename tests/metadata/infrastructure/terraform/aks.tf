resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
  tags = {
    "Environment" = "Anything"
  }
}

resource "azurerm_kubernetes_cluster" "example_aks_1" {
  name                = "example-aks-1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    tags = {
      Environment = "Production"
      Owner = "Alice@mail.com"
    }
    node_labels = {
      "domain.environment" = "production"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Production"
    Owner = "Alice@mail.com"
  }
}

resource "azurerm_kubernetes_cluster" "example_aks_2" {
  name                = "example-aks-2"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks2"

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_D2_v2"
    tags = {
      Environment = "Development"
      Owner = "Bob@mail.com"
    }
    # No node_labels specified
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Development"
    Owner = "Bob@mail.com"
  }
}

resource "azurerm_kubernetes_cluster" "example_aks_3" {
  name                = "example-aks-3"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks3"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D4_v3"
    # No tags specified
    node_labels = {
      "domain.environment" = "testing"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Testing"
    Owner = "Charlie"
  }
}

resource "azurerm_kubernetes_cluster" "example_aks_4" {
  name                = "example-aks-4"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks4"

  default_node_pool {
    name       = "default"
    node_count = 4
    vm_size    = "Standard_D2_v2"
    tags = {
      Environment = "Staging"
      Owner = "David"
    }
    node_labels = {
      "domain.environment" = "staging"
      "domain.owner"       = "david"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Staging"
    Owner = "David"
  }
}

resource "azurerm_kubernetes_cluster" "example_aks_5" {
  name                = "example-aks-5"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks5"

  default_node_pool {
    name       = "default"
    node_count = 5
    vm_size    = "Standard_D2_v2"
    # No tags or node_labels specified
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "QA"
    Owner = "Eve"
  }
}

resource "azurerm_kubernetes_cluster" "example_aks_6" {
  name                = "example-aks-6"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks6"

  default_node_pool {
    name       = "default"
    node_count = 6
    vm_size    = "Standard_D2_v2"
    tags = {
      Environment = "Production"
      Owner = "Frank@mail.com"
    }
    # No node_labels specified
  }

  identity {
    type = "SystemAssigned"
  }

  # No tags specified
}

resource "azurerm_kubernetes_cluster" "example_aks_7" {
  name                = "example-aks-7"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks7"

  default_node_pool {
    name       = "default"
    node_count = 7
    vm_size    = "Standard_D2_v2"
    # No tags specified
    node_labels = {
      "domain.environment" = "staging"
      "domain.owner"       = "george"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Staging"
    Owner = "George"
  }
}

resource "azurerm_kubernetes_cluster" "example_aks_8" {
  name                = "example-aks-8"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks8"

  default_node_pool {
    name       = "default"
    node_count = 8
    vm_size    = "Standard_D2_v2"
    tags = {
      Environment = "QA"
      Owner = "Hannah@mail.com"
    }
    node_labels = {
      "domain.environment" = "qa"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "QA"
    Owner = "Hannah@mail.com"
  }
}
