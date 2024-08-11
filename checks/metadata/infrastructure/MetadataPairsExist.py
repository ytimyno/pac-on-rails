from __future__ import annotations

from typing import TYPE_CHECKING, List, Any
import os, json, re

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


def flatten(nested_list):
    flat_list = []
    for item in nested_list:
        if isinstance(item, list):
            flat_list.extend(flatten(item))
        else:
            flat_list.append(item)
    return flat_list

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

def get_all_by_path_recursive(data, path, delimiter='.'):

    keys = path.split(delimiter)

    if isinstance(data.get(path),dict):
        return data
    
    try:
        return recursive_search(data, keys)
    except (KeyError, IndexError, TypeError):
        return []

def validate_one_of_tags(self, prefix, tag_path_attribute_required, conf, log_file, type_to_check):
    required_tags_validation = False
    required_tags_kvs = []
    valid_path_found = False

    # for each tag_path_attribute_required
    message = "Checking for metadata"
    for attribute in tag_path_attribute_required:

        check_attribute = f"{prefix+'.' if prefix else ''}{attribute['name']}"
        required_tags_kvs = flatten(get_all_by_path_recursive(conf, check_attribute, '.'))
        message = message + check_attribute

        if not isinstance(required_tags_kvs, list) or len(required_tags_kvs) < 1:
            # log_file.write("\nWARN3: Unexpected format for metadata in required_tags_kvs " + str(required_tags_kvs) + ".\n")
            log_file.write(f"\nWARN3: Unexpected format for metadata in required_tags_kvs extracted: {str(required_tags_kvs)}.\n")
            continue

        # Iterate tags found
        policied_tag_keys = []
        for required_tags_kvs_kv in required_tags_kvs:
            try:
                for k, v in required_tags_kvs_kv.items():
                    if k in self.metadata_to_check.keys():
                        allowed_values_pattern = re.compile(r"" + self.metadata_to_check[k]['allowed_values'])
                        if allowed_values_pattern.match(v):
                            # log_file.write("\nGOOD: Metadata "+k+" defined and within allowed values "+metadata_to_check[k]['allowed_values']+".\n") 
                            log_file.write(f"\nGOOD: Metadata {k} defined and within allowed values {self.metadata_to_check[k]['allowed_values']}.\n")
                            policied_tag_keys.append(k)
                            message += f" {k}: OK"
                            continue
                        else:
                            log_file.write(f"WARN: Metadata {k} exists in on_of_paths but its value ({v}) does not match allowed values {self.metadata_to_check[k]['allowed_values']}.\n")
                            # policied_tag_keys.append(k)
                            message += f" {k}: INVALID"
                            continue
            except:
                log_file.write(f"\nWARN2: Unexpected format for metadata in required_tags_kvs {str(required_tags_kvs)}.\n")
                continue

            # Convert keys to sets
            metadata_keys = set(self.metadata_to_check.keys())
            policied_tag_keys = set(policied_tag_keys)

            # Find missing keys
            missing_keys = metadata_keys - policied_tag_keys

            if not missing_keys:
                valid_path_found = True
                required_tags_validation = True
                break  # No need to check further paths if one valid path is found

    if not valid_path_found:
        paths_checked = "\n".join([f"\t\t\t{type_to_check}.{prefix}.{item['name']}" for item in tag_path_attribute_required])
        metadata_checked = "\n".join(f"\t\t\t{key}:{value['allowed_values']}" for key, value in self.metadata_to_check.items() if 'allowed_values' in value)
        
        log_message = (
            "\n\n\t**** SUMMARY OF FAILURE ****\n"
            "\n\t\tNo required CSP paths contain all policy-defined tags.\n"
            "\t\tMetadata attribute paths to check against:\n"
            f"{paths_checked}\n\n"
            "\t\tMetadata validated against:\n"
            f"{metadata_checked}\n\n"
            f"\t\tMetadata found: {required_tags_kvs}\n"
        )

        self.details.append(log_message)
        log_file.write(log_message)

    return required_tags_validation

def validate_required_tags(self, prefix, tag_path_attribute_required, conf, log_file, type_to_check):

    required_tags_validation = True
    required_tags_kvs = []

    # for each tag_path_attribute_required 
    for attribute in tag_path_attribute_required:
        check_attribute = f"{prefix+'.' if prefix else ''}{attribute['name']}"
        required_tags_kvs = flatten(get_all_by_path_recursive(conf, check_attribute,'.'))

        if not isinstance(required_tags_kvs, list) or len(required_tags_kvs) < 1:
            # self.details.append("\nWARN3: Unexpected format for metadata in required_tags_kvs " + str(required_tags_kvs) + ".\n")
            log_file.write("\nWARN3: Unexpected format for metadata in required_tags_kvs extracted: " + str(required_tags_kvs) + ".\n")
            required_tags_validation = False
            continue
        

        # Iterate tags found
        policied_tag_keys = []
        message = "Checking for metadata."
        for required_tags_kvs_kv in required_tags_kvs:
            try:
                for k,v in required_tags_kvs_kv.items():

                    if k in self.metadata_to_check.keys():
                        allowed_values_pattern = re.compile(r""+self.metadata_to_check[k]['allowed_values'])


                        if allowed_values_pattern.match(v):
                            # self.details.append("\nGOOD: Metadata "+k+" defined and within allowed values "+metadata_to_check[k]['allowed_values']+".\n") 
                            log_file.write("\nGOOD: Metadata "+k+" defined and within allowed values "+self.metadata_to_check[k]['allowed_values']+".\n")
                            policied_tag_keys.append(k)
                            message = message+" "+k+": OK"
                            continue

                        else:
                            self.details.append("WARN: Metadata "+k+" exists in on_of_paths but its value ("+v+") does not match allowed values "+self.metadata_to_check[k]['allowed_values'] + ".")
                            log_file.write("WARN: Metadata "+k+" exists in on_of_paths but its value ("+v+") does not match allowed values "+self.metadata_to_check[k]['allowed_values'] + ".")
                            policied_tag_keys.append(k)
                            message = message+" "+k+": INVALID"
                            required_tags_validation = False
                            continue
                        
            except:
                # self.details.append("\nWARN2: Unexpected format for metadata in required_tags_kvs " + str(required_tags_kvs) + ".\n")
                log_file.write("\nWARN2: Unexpected format for metadata in required_tags_kvs " + str(required_tags_kvs) + ".\n")
                required_tags_validation = False
            
            # Convert keys to sets
            metadata_keys = set(self.metadata_to_check.keys())
            policied_tag_keys = set(policied_tag_keys)

            # Find missing keys
            missing_keys = metadata_keys - policied_tag_keys
        
            if missing_keys:
                message = "Missing required key(s): " + ", ".join(missing_keys)
                required_tags_validation = False
        
    if not required_tags_validation:
        paths_checked = "\n".join([f"{type_to_check}.{prefix}.{item['name']}" for item in tag_path_attribute_required])
        metadata_checked = "\n".join(f"\t\t\t{key}:{value['allowed_values']}" for key, value in metadata_to_check.items() if 'allowed_values' in value)
        
        log_message = (
            "\n\n\t**** SUMMARY OF FAILURE ****\n"
            "\n\t\tRequired CSP paths do not contain all policy defined tags.\n\n"
            "\t\tMetadata attribute paths to check against:\n"
            f"\t\t\t{paths_checked}\n\n"
            "\t\tMetadata validated against:\n"
            f"{metadata_checked}\n\n"
            f"\t\tMetadata found: {required_tags_kvs}\n"
        )

        self.details.append(log_message)
        log_file.write(log_message)
    
    return required_tags_validation

class MetadataPairChecker(BaseResourceCheck):

    def __init__(self, metadata_to_check: List[dict], resource_types_to_check: List[dict]) -> None:
        name = "Ensure specified the IaC (Terraform) resource has the required metadata pairs (Azure tags / GCP labels)"
        id = "CKV_TF_METADATA_CHECK"

        # Policy File
        self.metadata_to_check = metadata_to_check

        # Resources Supported File
        self.resource_types_to_check = resource_types_to_check

        supported_resources_names = []

        # Python list comprehension allows us to do this
        supported_resources_names.extend(csp_supp_type['name']
            for csp_supp_v in resource_types_to_check.values()
            if 'supported_types' in csp_supp_v
            for csp_supp_type in csp_supp_v['supported_types']
        )

        categories = (CheckCategories.CONVENTION,)
        guideline = "This is a custom policy. Powered by Checkov and Python. Home: ytimyno/pac-on-rails.\n"

        formatted_metadata = "\n\t\tMetadata Required By Policy:\n"
        for key, value in metadata_to_check.items():
            formatted_metadata += f"\t\t\t{key}:\n"
            for sub_key, sub_value in value.items():
                formatted_metadata += f"\t\t\t\t{sub_key.capitalize()}: {sub_value}\n"

        guideline += formatted_metadata

        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources_names, guideline=guideline)

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
         
        tag_paths = []

        # Get the correct CSP specific metadata
        for type_to_check_k,type_to_check_v in self.resource_types_to_check.items():
            for type_to_check_key in type_to_check_v['keys']:
                if self.entity_type.startswith(type_to_check_key):
                    description = type_to_check_v['description']
                    for supported_type_path in type_to_check_v['supported_types']:
                        # If found supported resource type (expected), get its possible tag_paths
                        if self.entity_type == supported_type_path['name']:
                            tag_paths = supported_type_path['tag_paths']
                            break
                if len(tag_paths):
                    break
            if len(tag_paths):
                break

        if len(tag_paths) < 1:
            self.details.append("\tWARN: SKIP - No valid tag_paths for resource type "+ str(self.entity_type)+" \n")
            log_file.write("\tWARN: SKIP - No valid tag_paths for resource type "+ str(self.entity_type)+" \n")
            return CheckResult.SKIPPED


        metadata_keys_path_value = {}

        with open("scan_resource_metadata_"+self.entity_type+".log", '+a') as log_file:

            total_fail=True
            for tag_path in tag_paths:
                prefix = tag_path['path']

                # CHECK ONE OF TAGS
                tag_path_attribute_one_of = tag_path['attributes']['one_of']
                one_of_validation = False
                if len(tag_path_attribute_one_of)>0:
                    one_of_validation = validate_one_of_tags(self, prefix, tag_path_attribute_one_of, conf, log_file, self.entity_type)
                    
                    log_file.write(str(tag_path_attribute_one_of))

                    if not one_of_validation:
                        return CheckResult.FAILED
                    else:
                        total_fail = False
                
                # CHECK REQUIRED TAGS
                required_tag_paths = tag_path['attributes']['required']
                required_validation = False
                if len(required_tag_paths)>0:
                    required_validation = validate_required_tags(self, prefix, required_tag_paths, conf, log_file, self.entity_type)
                    
                    if not required_validation:
                        return CheckResult.FAILED
                    else:
                        total_fail = False
                
            if total_fail:
                return CheckResult.FAILED
            
            return CheckResult.PASSED

policy_file_name = 'policy.json'

default_metadata_pairs = {
    "Environment": {
        "allowed_values": ".*",
        "version": "1.0",
        "description": "A sample label - Any value accepted"
    },
    "Owner": {
        "allowed_values": "^[\\w\\.-]+@[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}$",
        "version": "1.0",
        "description": "A sample label - Any value accepted"
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
        "supported_types": [
            {
                "name": "azurerm_kubernetes_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
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
                                },
                                {
                                    "name": "node_labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_availability_set",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_capacity_reservation",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_capacity_reservation_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dedicated_host",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dedicated_host_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_disk_access",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_disk_encryption_set",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_gallery_application",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_gallery_application_version",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_image",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_linux_virtual_machine",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_linux_virtual_machine",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_linux_virtual_machine_scale_set",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_managed_disk",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_orchestrated_virtual_machine_scale_set",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_shared_image",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_shared_image_gallery",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_shared_image_version",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_snapshot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_ssh_public_key",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_machine",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_machine_extension",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_machine_restore_point_collection",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_machine_run_command",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_machine_scale_set",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_windows_virtual_machine",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_windows_virtual_machine_scale_set",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_resource_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_service_plan",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_service_managed_certificate",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_service_environment_v3",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_service_environment",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_service_certificate",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_configuration_key",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_configuration_feature",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_configuration",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_analysis_services_server",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_active_directory_domain_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_api_management",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_arc_private_link_scope",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_arc_machine_extension",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_machine_learning_compute_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_machine_learning_compute_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_kubernetes_cluster_node_pool",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                },
                                {
                                    "name": "node_labels",
                                    "cloud_native": True
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_app_service_slot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_function_app",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_function_app_slot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_linux_function_app",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_linux_function_app_slot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_linux_web_app",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_linux_web_app_slot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_service_plan",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_static_site",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_static_web_app",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_windows_function_app",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_windows_function_app_slot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_windows_web_app",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_windows_web_app_slot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_application_insights",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_application_insights_standard_web_test",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_application_insights_web_test",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_application_insights_workbook",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_application_insights_workbook_template",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_arc_resource_bridge_appliance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_arc_kubernetes_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_arc_kubernetes_cluster_extension",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_attestation_provider",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_user_assigned_identity",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_automanage_configuration",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_automation_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_automation_dsc_configuration",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_automation_powershell72_module",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_automation_python3_package",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_automation_runbook",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_automation_watcher",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_managed_lustre_file_system",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_stack_hci_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_stack_hci_logical_network",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_vmware_private_cloud",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_subscription",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_batch_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_bot_channels_registration",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_bot_connection",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_healthbot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_bot_service_azure_bot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_bot_web_app",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_cdn_endpoint",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_cdn_frontdoor_endpoint",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_cdn_frontdoor_firewall_policy",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_cdn_frontdoor_profile",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_cdn_profile",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_cognitive_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_communication_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_email_communication_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_email_communication_service_domain",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_confidential_ledger",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_api_connection",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_container_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_container_registry",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    },
                    {
                        "path": "georeplications",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_container_registry_agent_pool",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_container_registry_task",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_container_registry_webhook",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_kubernetes_fleet_manager",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_container_app",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_container_app_environment",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_container_app_environment_certificate",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_container_app_job",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_cosmosdb_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_cosmosdb_cassandra_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_cosmosdb_postgresql_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_custom_provider",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_a_record",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_aaaa_record",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_caa_record",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_cname_record",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_mx_record",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_ns_record",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_ptr_record",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_srv_record",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_txt_record",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dns_zone",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_dashboard_grafana",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_application_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_application_security_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_bastion_host",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_custom_ip_prefix",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_express_route_circuit",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_express_route_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_express_route_port",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_firewall",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_firewall_policy",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_frontdoor",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_frontdoor_firewall_policy",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_ip_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_local_network_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_nat_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_connection_monitor",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_ddos_protection_plan",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_interface",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_manager",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_profile",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_security_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_watcher",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_watcher_flow_log",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_point_to_site_vpn_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_private_endpoint",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_private_link_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_public_ip",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_public_ip_prefix",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_route_filter",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_route_server",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_route_table",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_subnet_service_endpoint_storage_policy",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_traffic_manager_profile",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_hub",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_hub_security_partner_provider",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_network",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_network_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_network_gateway_connection",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_virtual_wan",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_vpn_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_vpn_server_configuration",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_vpn_site",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_web_application_firewall_policy",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_kusto_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_data_factory",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_data_factory_linked_service_azure_databricks",
                "tag_paths": [
                    {
                        "path": "new_cluster_config",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "custom_tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_data_share_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_data_protection_backup_vault",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_data_protection_resource_guard",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mariadb_server",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mssql_database",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mssql_elasticpool",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mssql_failover_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mssql_job_agent",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mssql_managed_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mssql_server",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mssql_virtual_machine",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mssql_virtual_machine_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mysql_flexible_server",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mysql_server",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_postgresql_flexible_server",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_postgresql_server",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_sql_database",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_sql_elasticpool",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_sql_failover_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_sql_managed_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_sql_server",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_key_vault",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_key_vault_certificate",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_key_vault_key",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_key_vault_managed_hardware_security_module",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_key_vault_managed_hardware_security_module_key",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_key_vault_managed_storage_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_key_vault_managed_storage_account_sas_token_definition",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_key_vault_secret",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_lb",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_load_test",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_log_analytics_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_log_analytics_query_pack",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_log_analytics_query_pack_query",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_log_analytics_saved_search",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_log_analytics_solution",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_log_analytics_workspace",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_integration_service_environment",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_logic_app_integration_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_logic_app_standard",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_logic_app_workflow",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_logz_monitor",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_logz_sub_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_machine_learning_datastore_blobstorage",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_machine_learning_datastore_datalake_gen2",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_machine_learning_datastore_fileshare",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_machine_learning_inference_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_machine_learning_synapse_spark",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_machine_learning_workspace",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_managed_application",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_managed_application_definition",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_maintenance_configuration",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_maps_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_maps_creator",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_media_live_event",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_media_services_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_media_streaming_endpoint",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_eventgrid_domain",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_eventgrid_system_topic",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_eventgrid_topic",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_eventhub_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_eventhub_namespace",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_notification_hub",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_notification_hub_namespace",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_relay_namespace",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_servicebus_namespace",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_signalr_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_web_pubsub",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_spatial_anchors_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network_attached_data_network",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network_data_network",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network_packet_core_control_plane",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network_packet_core_data_plane",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network_sim_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network_sim_policy",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network_site",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_mobile_network_slice",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_action_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_action_rule_action_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_action_rule_suppression",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_activity_log_alert",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_alert_processing_rule_action_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_alert_processing_rule_suppression",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_alert_prometheus_rule_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_autoscale_setting",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_data_collection_endpoint",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_data_collection_rule",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_metric_alert",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_private_link_scope",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_scheduled_query_rules_alert",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_scheduled_query_rules_alert_v2",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_scheduled_query_rules_log",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_smart_detector_alert_rule",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_monitor_workspace",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_function_azure_traffic_collector",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_network_function_collector_policy",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_hpc_cache",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_storage_account",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_storage_sync",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_management_group_template_deployment",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_resource_deployment_script_azure_cli",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_resource_deployment_script_azure_power_shell",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_resource_group_template_deployment",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_subscription_template_deployment",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_tenant_template_deployment",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_workloads_sap_discovery_virtual_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_workloads_sap_single_node_virtual_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "azurerm_workloads_sap_three_tier_virtual_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "tags",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            }
        ]
    },
    "google": {
        "keys": [
            "gcp",
            "google",
            "googlecloud"
        ],
        "description": "Resources to check for metadata pairs (GCP). To override this, modify this file, leaving it in the working directory checkov runs from.",
        "supported_types": [
            {
                "name": "google_container_cluster",
                "tag_paths": [
                    {
                        "path": "node_config",
                        "attributes": {
                            "one_of": [
                                {
                                    "name": "resource_labels",
                                    "cloud_native": False
                                },
                                {
                                    "name": "labels",
                                    "cloud_native": True
                                },
                                {
                                    "name": "user_labels",
                                    "cloud_native": False
                                }
                            ],
                            "required": []
                        }
                    },
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [
                                {
                                    "name": "resource_labels",
                                    "cloud_native": False
                                },
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                },
                                {
                                    "name": "user_labels",
                                    "cloud_native": False
                                }
                            ],
                            "required": []
                        }
                    }
                ]
            },
            {
                "name": "google_api_gateway_api",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_api_gateway_api_config",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_api_gateway_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_alloydb_backup",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_alloydb_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_alloydb_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_gkeonprem_bare_metal_admin_cluster",
                "tag_paths": [
                    {
                        "path": "control_plane.control_plane_node_pool_config.node_pool_config",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": True
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_gkeonprem_bare_metal_cluster",
                "tag_paths": [
                    {
                        "path": "control_plane.control_plane_node_pool_config.node_pool_config",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": True
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_gkeonprem_bare_metal_node_pool",
                "tag_paths": [
                    {
                        "path": "control_plane.control_plane_node_pool_config.node_pool_config",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": True
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_gkeonprem_vmware_node_pool",
                "tag_paths": [
                    {
                        "path": "config",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": True
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_artifact_registry_repository",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_assured_workloads_workload",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_gke_backup_backup_plan",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_gke_backup_restore_plan",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_beyondcorp_app_connection",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_beyondcorp_app_connector",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_beyondcorp_app_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_bigquery_dataset",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_bigquery_job",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_bigquery_table",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_blockchain_node_engine_blockchain_nodes",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_privateca_ca_pool",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_privateca_certificate",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_privateca_certificate_authority",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_privateca_certificate_template",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_certificate_manager_certificate",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_certificate_manager_certificate_issuance_config",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_certificate_manager_certificate_map",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_certificate_manager_certificate_map_entry",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_certificate_manager_dns_authorization",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_certificate_manager_trust_config",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_monitoring_alert_policy",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "user_labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_monitoring_custom_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "user_labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_monitoring_notification_channel",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "user_labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_monitoring_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "user_labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_monitoring_slo",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "user_labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_monitoring_uptime_check_config",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "user_labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_notebooks_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_notebooks_runtime",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_bigtable_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_composer_environment",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dns_managed_zone",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_data_fusion_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_clouddeploy_automation",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_clouddeploy_custom_target_type",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_clouddeploy_delivery_pipeline",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_clouddeploy_target",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_deployment_manager_deployment",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_clouddomains_registration",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_cloudfunctions_function",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_cloudfunctions2_function",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_healthcare_consent_store",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_healthcare_dicom_store",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_healthcare_fhir_store",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_healthcare_hl7_v2_store",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_kms_crypto_key",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_project",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_pubsub_subscription",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_pubsub_topic",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_cloud_run_v2_job",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_cloud_run_v2_service",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    },{
                        "path": "template",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_sql_database_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "user_labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_spanner_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_spanner_instance_config",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_storage_bucket",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_tpu_node",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_tpu_v2_vm",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_workstations_workstation",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_workstations_workstation_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_workstations_workstation_config",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_address",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_disk",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_external_vpn_gateway",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_forwarding_rule",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_global_address",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_global_forwarding_rule",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_image",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_instance",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    },
                    {
                        "path": "boot_disk.initialize_params",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_instance_from_machine_image",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_instance_from_template",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_instance_group_manager",
                "tag_paths": [
                    {
                        "path": "all_instances_config",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_instance_template",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_interconnect",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_region_disk",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_region_instance_group_manager",
                "tag_paths": [
                    {
                        "path": "all_instances_config",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_region_instance_template",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_vpn_tunnel",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_resource_policy",
                "tag_paths": [
                    {
                        "path": "snapshot_properties",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_compute_snapshot",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_container_aws_node_pool",
                "tag_paths": [
                    {
                        "path": "config",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_container_azure_node_pool",
                "tag_paths": [
                    {
                        "path": "config",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_data_loss_prevention_job_trigger",
                "tag_paths": [
                    {
                        "path": "inspect_job.storage_config.hybrid_options",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_database_migration_service_connection_profile",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_database_migration_service_private_connection",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataflow_flex_template_job",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataflow_job",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataform_repository",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataplex_aspect_type",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataplex_asset",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataplex_datascan",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataplex_entry_group",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataplex_entry_type",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataplex_lake",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataplex_task",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataplex_zone",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataproc_cluster",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataproc_job",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "name": "google_dataproc_workflow_template",
                "tag_paths": [
                    {
                        "path": "",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    },
                    {
                        "path": "jobs",
                        "attributes": {
                            "one_of": [],
                            "required": [
                                {
                                    "name": "labels",
                                    "cloud_native": False
                                }
                            ]
                        }
                    }
                ]
            }
        ]
    }
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
