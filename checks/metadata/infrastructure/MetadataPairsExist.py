from __future__ import annotations

from typing import TYPE_CHECKING, List, Any
import os, json, re

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


def flatten(l):
    if not isinstance(l, list):
        return [l]
    flat = []
    for sublist in l:
        flat.extend(flatten(sublist))
    return flat

def get_all_by_path_recursive(data, path, delimiter='.'):

    keys = path.split(delimiter)

    if isinstance(data.get(path),dict):
        return data
    
    def recursive_search(data, keys):
        if not keys:
            return data

        current_key = keys[0]
        remaining_keys = keys[1:]

        if isinstance(data, list):
            results = []
            for item in data:
                try:
                    results.append(recursive_search(item, keys))
                except (KeyError, IndexError, TypeError):
                    continue
            return results
        elif isinstance(data, dict):
            if current_key in data:
                return recursive_search(data[current_key], remaining_keys)
            else:
                raise KeyError(f"Key '{current_key}' not found in dictionary")
        else:
            raise TypeError(f"Expected list or dict, got {type(data)}")

    try:
        return recursive_search(data, keys)
    except (KeyError, IndexError, TypeError):
        return None

class MetadataPairChecker(BaseResourceCheck):

    def __init__(self, metadata_to_check: List[dict], resource_types_to_check: List[dict]) -> None:
        name = "Ensure specified the IaC (Terraform) resource has the required metadata pairs (Azure tags / GCP labels)"
        id = "CKV_TF_METADATA_CHECK"

        self.metadata_to_check = metadata_to_check
        self.resource_types_to_check = resource_types_to_check

        supported_resources = []
        for csp,csp_supp in resource_types_to_check.items():
            if 'supported_types' in csp_supp:
                supported_resources = supported_resources + csp_supp['supported_types']
            

        categories = (CheckCategories.CONVENTION,)
        guideline = "This is a custom policy. Powered by Checkov and Python. Home: ytimyno/pac-on-rails"

        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
         
        resource_type = self.entity_type
        
        # Get the correct CSP specific metadata
        for type_to_check_keys,type_to_check_value in self.resource_types_to_check.items():
            for key in type_to_check_value['keys']:
                if resource_type.startswith(key):
                    description = type_to_check_value['description']
                    tag_paths = type_to_check_value['tag_paths']
                    break

        metadata_keys_path_value = {}

        with open("scan_resource_metadata_"+self.entity_type+".log", '+a') as log_file:

            log_file.write("\nValidating against:\n")
            json.dump(self.metadata_to_check, log_file, indent=4)

            found_tag = False
            invalid_tag_paths = []
            valid_paths = []

            for tag_path in tag_paths:
                prefix = tag_path['path']

                # # Extract attributes from tag_config
                one_of = tag_path['attributes']['one_of']
                required = tag_path['attributes']['required']
                all = tag_path['attributes']['all']
                optional = tag_path['attributes']['optional']

                
            return CheckResult.PASSED

policy_file_name = 'policy.json'

default_metadata_pairs = {
    "maintainer": {
        "allowed_values": ".*",
        "version": "1.0",
        "description": "A sample metadata pair - Any value accepted. To override this, create a "+policy_file_name+" file in the working directory checkov runs from."
    }, 
    "maintainer_specific":{
        "allowed_values": "^[\w\.-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$",
        "version": "1.0",
        "description": "A sample metadata pair - Specific regex. To override this, create a "+policy_file_name+" file in the working directory checkov runs from."
    },
    "random_label_key":{
        "allowed_values": "random_label_value",
        "version": "1.0",
        "description": "A sample metadata pair - This will fail (unless you do have that unspecified_random_label). To override this, create a "+policy_file_name+" file in the working directory checkov runs from."
    }
}

if os.path.exists(policy_file_name):
    # If the file exists, open and read the JSON data
    with open(policy_file_name, 'r') as file:
        try:
            metadata_to_check = json.load(file)
        except:
            metadata_to_check = default_metadata_pairs
else:
    # If the file doesn't exist, use the default dictionary
    metadata_to_check = default_metadata_pairs

cloud_specific_conf_file_name = 'cloud_specific_configurations.json'

default_resources_types = {
    "azure": {
        "keys": [
            "arm",
            "az",
            "azure",
            "azurerm"
        ],
        "description": "Resources to check for metadata pairs (Azure). To override this, modify this file, leaving it in the working directory checkov runs from.",
        "tag_paths": [
            {
                "path": "",
                "attributes": {
                    "one_of": [
                        {
                            "name": "tags",
                            "cloud_native": False
                        }
                    ],
                    "required": [],
                    "all": [],
                    "optional": []
                }
            },
            {
                "path": "default_node_pool",
                "attributes": {
                    "one_of": [],
                    "required": [
                        {
                            "name": "tags",
                            "cloud_native": False
                        }
                    ],
                    "all": [],
                    "optional": [
                        {
                            "name": "node_labels",
                            "cloud_native": True
                        }
                    ]
                }
            }
        ],
        "supported_types": [
            "azurerm_hpc_cache_blob_target",
            "azurerm_hpc_cache_nfs_target",
            "azurerm_storage_account",
            "azurerm_storage_account_customer_managed_key",
            "azurerm_storage_account_network_rules",
            "azurerm_storage_blob",
            "azurerm_storage_container",
            "azurerm_storage_data_lake_gen2_filesystem",
            "azurerm_storage_management_policy",
            "azurerm_storage_queue",
            "azurerm_storage_share",
            "azurerm_storage_share_directory",
            "azurerm_storage_table",
            "azurerm_storage_table_entity",
            "azurerm_stream_analytics_function_javascript_udf",
            "azurerm_stream_analytics_job",
            "azurerm_stream_analytics_output_blob",
            "azurerm_stream_analytics_output_eventhub",
            "azurerm_stream_analytics_output_mssql",
            "azurerm_stream_analytics_output_servicebus_queue",
            "azurerm_stream_analytics_output_servicebus_topic",
            "azurerm_stream_analytics_reference_input_blob",
            "azurerm_stream_analytics_stream_input_blob",
            "azurerm_stream_analytics_stream_input_eventhub",
            "azurerm_stream_analytics_stream_input_iothub",
            "azurerm_synapse_workspace",
            "azurerm_template_deployment",
            "azurerm_iot_time_series_insights_access_policy",
            "azurerm_iot_time_series_insights_reference_data_set",
            "azurerm_iot_time_series_insights_standard_environment"
        ]
    },
    "google": {
        "keys": [
            "gcp",
            "google",
            "googlecloud"
        ],
        "description": "Resources to check for metadata pairs (GCP). To override this, modify this file, leaving it in the working directory checkov runs from.",
        "tag_paths": [
            {
                "path": "",
                "attributes": {
                    "one_of": [
                        {
                            "name": "resource_labels",
                            "cloud_native": False
                        },
                        {
                            "name": "user_labels",
                            "cloud_native": False
                        },
                        {
                            "name": "labels",
                            "cloud_native": False
                        }
                    ],
                    "required": [],
                    "all": [],
                    "optional": []
                }
            },
            {
                "path": "node_config",
                "attributes": {
                    "one_of": [],
                    "required": [
                        {
                            "name": "resource_labels",
                            "cloud_native": False
                        }
                    ],
                    "all": [],
                    "optional": [
                        {
                            "name": "labels",
                            "cloud_native": True
                        }
                    ]
                }
            }
        ],
        "supported_types": [
            "google_compute_instance",
            "google_storage_bucket",
            "google_bigquery_dataset",
            "google_pubsub_topic",
            "google_sql_database_instance",
            "google_container_cluster",
            "google_cloudfunctions_function",
            "google_cloud_run_service",
            "google_dataproc_cluster",
            "google_filestore_instance",
            "google_compute_disk",
            "google_compute_firewall",
            "google_compute_subnetwork",
            "google_compute_network",
            "google_compute_forwarding_rule",
            "google_compute_instance_template",
            "google_compute_router",
            "google_compute_router_nat",
            "google_compute_instance_group",
            "google_compute_instance_group_manager",
            "google_compute_target_instance",
            "google_kms_key_ring",
            "google_kms_crypto_key",
            "google_spanner_instance",
            "google_spanner_database",
            "google_cloud_scheduler_job",
            "google_cloudbuild_trigger",
            "google_dataflow_job",
            "google_datafusion_instance",
            "google_bigtable_instance",
            "google_bigtable_table"
        ]
    },
   }


if os.path.exists(cloud_specific_conf_file_name):
    # If the file exists, open and read the JSON data
    with open(cloud_specific_conf_file_name, 'r') as file:
        try:
            resource_types_to_check = json.load(file)
        except:
            resource_types_to_check = default_resources_types
else:
    # If the file doesn't exist, use the default dictionary
    resource_types_to_check = default_resources_types

check = MetadataPairChecker(metadata_to_check, resource_types_to_check)
