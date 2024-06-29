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