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


resource "google_gkeonprem_bare_metal_cluster" "default-basic" {
  name = "my-cluster"
  location = "us-west1"
  admin_cluster_membership = "projects/870316890899/locations/global/memberships/gkeonprem-terraform-test"
  bare_metal_version = "1.12.3"
  network_config {
    island_mode_cidr {
      service_address_cidr_blocks = ["172.26.0.0/16"]
      pod_address_cidr_blocks = ["10.240.0.0/13"]
    }
  }
  control_plane {
    control_plane_node_pool_config {
      node_pool_config {
        labels = {}
        operating_system = "LINUX"
        node_configs {
          labels = {}
          node_ip = "10.200.0.9"
        }
      }
    }
  }
  load_balancer {
    port_config {
      control_plane_load_balancer_port = 443
    }
    vip_config {
      control_plane_vip = "10.200.0.13"
      ingress_vip = "10.200.0.14"
    }
    metal_lb_config {
      address_pools {
        pool = "pool1"
        addresses = [
          "10.200.0.14/32",
          "10.200.0.15/32",
          "10.200.0.16/32",
          "10.200.0.17/32",
          "10.200.0.18/32",
          "fd00:1::f/128",
          "fd00:1::10/128",
          "fd00:1::11/128",
          "fd00:1::12/128"
        ]
      }
    }
  }
  storage {
    lvp_share_config {
      lvp_config {
        path = "/mnt/localpv-share"
        storage_class = "local-shared"
      }
      shared_path_pv_count = 5
    }
    lvp_node_mounts_config {
      path = "/mnt/localpv-disk"
      storage_class = "local-disks"
    }
  }
  security_config {
    authorization {
      admin_users {
        username = "admin@hashicorptest.com"
      }
    }
  }
}

resource "google_gkeonprem_bare_metal_node_pool" "nodepool-basic" {
  name =  "my-nodepool"
  bare_metal_cluster =  google_gkeonprem_bare_metal_cluster.default-basic.name
  location = "us-west1"
  node_pool_config {
    operating_system = "LINUX"
    node_configs {
      node_ip = "10.200.0.11"
    }
  }
}



data "google_project" "project" {}

resource "google_secret_manager_secret" "example-remote-secret" {
  secret_id = "example-secret"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "example-remote-secret_version" {
  secret = google_secret_manager_secret.example-remote-secret.id
  secret_data = "remote-password"
}

resource "google_secret_manager_secret_iam_member" "secret-access" {
  secret_id = google_secret_manager_secret.example-remote-secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-artifactregistry.iam.gserviceaccount.com"
}

resource "google_artifact_registry_repository" "my-repo" {
  location      = "us-central1"
  repository_id = "example-python-custom-remote"
  description   = "example remote custom python repository with credentials"
  format        = "PYTHON"
  mode          = "REMOTE_REPOSITORY"
  labels = {
    Environment = "hi"
    Owner = "hi"
  }
  remote_repository_config {
    description = "custom npm with credentials"
    disable_upstream_validation = true
    python_repository {
      custom_repository {
        uri = "https://my.python.registry"
      }
    }
    upstream_credentials {
      username_password_credentials {
        username = "remote-username"
        password_secret_version = google_secret_manager_secret_version.example-remote-secret_version.name
      }
    }
  }
}



resource "google_compute_health_check" "autohealing" {
  name                = "autohealing-health-check"
  check_interval_sec  = 5
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 10 # 50 seconds

  http_health_check {
    request_path = "/healthz"
    port         = "8080"
  }
}

resource "google_compute_instance_group_manager" "appserver" {
  name = "appserver-igm"

  base_instance_name = "app"
  zone               = "us-central1-a"

  version {
    instance_template  = google_compute_instance_template.appserver.self_link_unique
  }

  all_instances_config {
    metadata = {
      metadata_key = "metadata_value"
    }
    labels = {
      Environment = "label_value"
      Owner = "user@domain.com"
    }
  }

  target_pools = [google_compute_target_pool.appserver.id]
  target_size  = 2

  named_port {
    name = "customhttp"
    port = 8888
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.autohealing.id
    initial_delay_sec = 300
  }
}