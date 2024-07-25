provider "google" {
  project = var.project
  region  = var.region
}

variable "project" {}
variable "region" {}

resource "google_container_cluster" "example_gke_1" {
  name               = "example-gke-1"
  location           = "us-central1-a"
  initial_node_count = 3

  resource_labels = {
    Environment = "Production"
    Owner = "Alice"
  }

  private_cluster_config {}

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    tags = ["foo", "bar"]
    labels = {
      Environment = "Production"
      Owner = "Alice"
    }
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "example_gke_2" {
  name               = "example-gke-2"
  location           = "us-central1-b"
  initial_node_count = 3

  resource_labels = {
    Environment = "Development"
    Owner = "Bob"
  }

  private_cluster_config {}

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    tags = ["baz", "qux"]
    labels = {
      Environment = "Development"
      Owner = "Bob"
    }
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "example_gke_3" {
  name               = "example-gke-3"
  location           = "us-central1-c"
  initial_node_count = 3

  resource_labels = {
    Environment = "Testing"
    Owner = "Charlie"
  }

  private_cluster_config {}

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    # No resource_labels specified
    labels = {
      Environment = "Testing"
      Owner = "Charlie"
    }
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "example_gke_4" {
  name               = "example-gke-4"
  location           = "us-central1-d"
  initial_node_count = 3

  # No resource_labels specified

  private_cluster_config {}

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    tags = ["staging"]

    labels = {
      Environment = "Staging"
      Owner = "David"
    }
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "example_gke_5" {
  name               = "example-gke-5"
  location           = "us-central1-e"
  initial_node_count = 3

  resource_labels = {
    Environment = "QA"
    Owner = "Eve@mail.com"
  }

  private_cluster_config {}

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    # No labels or resource_labels specified
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "example_gke_6" {
  name               = "example-gke-6"
  location           = "us-central1-f"
  initial_node_count = 3

  resource_labels = {
    Environment = "Production"
    Owner = "Frank@mail.com"
  }

  private_cluster_config {}

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    tags = ["prod"]
    # No labels or resource_labels specified
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "example_gke_7" {
  name               = "example-gke-7"
  location           = "us-central1-g"
  initial_node_count = 3

  resource_labels = {
    Environment = "Staging"
    Owner = "George@mail.com"
  }

  private_cluster_config {}

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    # No resource_labels specified
    labels = {
      Environment = "Staging"
      Owner = "George@mail.com"
    }
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "example_gke_8" {
  name               = "example-gke-8"
  location           = "us-central1-h"
  initial_node_count = 3

  resource_labels = {
    Environment = "QA"
    Owner = "Hannah@gm.com"
  }

  private_cluster_config {}

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    tags = ["qa"]
    labels = {
      Environment = "QA"
      Owner = "Hannah"
    }
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}


resource "google_container_cluster" "example_gke_9" {
  name               = "example-gke-9"
  location           = "us-central1-h"
  initial_node_count = 3

  resource_labels = {
    Environment = "QA"
    Owner = "Hannah@gm.com"
  }

  private_cluster_config {}

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    tags = ["qa"]
    labels = {
      Environment = "QA"
      Owner = "Hannah@gm.com"
    }
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}