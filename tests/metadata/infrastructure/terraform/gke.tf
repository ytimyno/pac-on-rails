resource "google_container_cluster" "primary" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  resource_labels = {
    ssa = "xzd"
  }
  private_cluster_config {

  }

  network_policy {
    enabled = true
  }

  ip_allocation_policy {

  }

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }


  node_config {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    labels = {
      foo = "bar"
    }
    tags = ["foo", "bar"]
    resource_labels = {
      ssa = "xzd"
    }
  }
  timeouts {
    create = "30m"
    update = "40m"
  }
}
