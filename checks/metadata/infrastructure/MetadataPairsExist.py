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
                            policied_tag_keys.append(k)
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
            "\n\t\tRequired CSP paths do not contain all policy defined tags.\n"
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
        "allowed_values": ".*",
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
        "tag_paths_strict": False,
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
