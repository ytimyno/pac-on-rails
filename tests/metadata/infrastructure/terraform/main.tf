resource "aws_s3_bucket" "credit_cards_bucket" {
  region        = var.region
  bucket        = local.bucket_name
  force_destroy = true

  tags = {
    maintainer = "Hello",
    maintainer_specific = "this.is.an@email.com"
    random_label_key = "random_label_value"
  }
}

variable "region" {
  default = "europe"
}
variable "bucket_name" {
  default = "mybucketname"
}
variable "email" {
  default = "null@gmail.com"
}
locals {
  bucket_name = ""
}

resource "google_service_account" "default" {
  account_id   = "my-custom-sa"
  display_name = "Custom SA for VM Instance"
}

resource "google_compute_instance" "default" {
  name         = "my-instance"
  machine_type = "n2-standard-2"
  zone         = "us-central1-a"
  shielded_instance_config {
    enable_secure_boot = true
  }

  tags = ["foo", "bar"]
  labels = {
    maintainer = "hi"
    maintainer_specific = var.email,
  }


  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      labels = {
        maintainer = "hi"
        maintainer_specific = "nothh@email.com",
      }
    }
  }

  // Local SSD disk
  scratch_disk {
    interface = "NVME"
  }

  network_interface {
    network = "default"
    
    
    access_config {
      // Ephemeral public IP
      
    }
  }

  metadata = {
    foo = "bar"
  }

  metadata_startup_script = "echo hi > /test.txt"

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.default.email
    scopes = ["cloud-platform"]
  }
}


provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
  tags = {
    maintainer = "Hello",
    maintainer_specific = "this.is.an@email.com"
    random_label_key = "random_label_value"
  }
}

resource "azurerm_virtual_network" "example" {
  name                = "example-network"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tags = {
    maintainer = "Hello",
    maintainer_specific = "this.is.an@email.com"
    random_label_key = "random_label_value"
  }
}

resource "azurerm_subnet" "example" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_interface" "example" {
  name                = "example-nic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tags = {
    maintainer = "Hello",
    maintainer_specific = "this.is.an@email.com"
    random_label_key = "random_label_value"
  }

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  
  }
}

resource "azurerm_windows_virtual_machine" "example" {
  name                = "example-machine"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  admin_username      = "adminuser"
  admin_password      = "P@$$w0rd1234!"
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]
  tags = {
    maintainer = "Hello",
    maintainer_specific = "this.is.an@email.com"
    random_label_key = "random_label_value"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"

  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter"
    version   = "latest"
  }
}