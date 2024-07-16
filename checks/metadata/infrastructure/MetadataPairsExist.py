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

            for tag_path in tag_paths:
                prefix = tag_path['path']

                one_of = tag_path['attributes']['one_of']
                one_of_tags_status = False
                for attribute in one_of:
                    if prefix:
                        check_attribute = prefix+"."+attribute['name']
                    else:
                        check_attribute = attribute['name']

                    one_of_tags = flatten(get_all_by_path_recursive(conf, check_attribute,'.'))

                    if one_of_tags and isinstance(one_of_tags, list):
                        for one_of_tag in one_of_tags:
                            try:
                                for k,v in one_of_tag.items():

                                    if k in self.metadata_to_check.keys():
                                        allowed_values_pattern = re.compile(r""+self.metadata_to_check[k]['allowed_values'])
                                    
                                        if allowed_values_pattern.match(v):
                                            # self.details.append("\nGOOD: Metadata "+k+" defined and within allowed values "+metadata_to_check[k]['allowed_values']+".\n") 
                                            log_file.write("\nGOOD: Metadata "+k+" defined and within allowed values "+self.metadata_to_check[k]['allowed_values']+".\n")
                                            one_of_tags_status = True
                                            continue

                                        else:
                                            self.details.append("WARN: Metadata "+k+" exists in on_of_paths but its value ("+v+") does not match allowed values "+self.metadata_to_check[k]['allowed_values'] + ".")
                                            log_file.write("WARN: Metadata "+k+" exists in on_of_paths but its value ("+v+") does not match allowed values "+self.metadata_to_check[k]['allowed_values'] + ".")
                                            continue
                                        
                            except:
                                self.details.append("\nWARN2: Unexpected format for metadata in one_of_tags " + str(one_of_tags) + ".\n")
                                log_file.write("\nWARN2: Unexpected format for metadata in one_of_tags " + str(one_of_tags) + ".\n")

                    else:          
                        # print
                        # self.details.append("\nWARN3: Unexpected format for metadata in one_of_tags " + str(one_of_tags) + ".\n")
                        log_file.write("\nWARN3: Unexpected format for metadata in one_of_tags " + str(one_of_tags) + ".\n")
                        continue
                    
                if not one_of_tags_status:
                    self.details.append("\nFAIL: No valid one_of tags found. Checked paths "+ str(one_of) +", only found " + str(one_of_tags) + ".\n")
                    log_file.write("\nFAIL: No valid one_of tags found. Checked paths "+ str(one_of) +", only found " + str(one_of_tags) + ".\n")
                    return CheckResult.FAILED

                

                # required = tag_path['attributes']['required']
                # for attribute in required:
                #     if prefix:
                #         check_attribute = prefix+"."+attribute['name']
                #     else:
                #         check_attribute = attribute['name']

                #     required_tags = get_all_by_path_recursive(conf, check_attribute,'.')
                #     print(flatten(required_tags))



                # all = tag_path['attributes']['all']
                # for attribute in all:
                #     if prefix:
                #         check_attribute = prefix+"."+attribute['name']
                #     else:
                #         check_attribute = attribute['name']

                #     all_tags = get_all_by_path_recursive(conf, check_attribute,'.')
                #     print(flatten(all_tags))


                # optional = tag_path['attributes']['optional']
                # for attribute in optional:
                #     print(prefix + "." + attribute['name'])
                #     if prefix:
                #         check_attribute = prefix+"."+attribute['name']
                #     else:
                #         check_attribute = attribute['name']

                #     optional_tags = get_all_by_path_recursive(conf, check_attribute,'.')
                #     print(flatten(optional_tags))

                
            return CheckResult.PASSED

policy_file_name = 'policy.json'

default_metadata_pairs = {
    "Environment": {
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
            "azurerm_api_management",
            "azurerm_api_management_api",
            "azurerm_api_management_api_operation",
            "azurerm_api_management_api_operation_policy",
            "azurerm_api_management_api_policy",
            "azurerm_api_management_api_schema",
            "azurerm_api_management_api_version_set",
            "azurerm_api_management_authorization_server",
            "azurerm_api_management_backend",
            "azurerm_api_management_certificate",
            "azurerm_api_management_diagnostic",
            "azurerm_api_management_group",
            "azurerm_api_management_group_user",
            "azurerm_api_management_identity_provider_aad",
            "azurerm_api_management_identity_provider_facebook",
            "azurerm_api_management_identity_provider_google",
            "azurerm_api_management_identity_provider_microsoft",
            "azurerm_api_management_identity_provider_twitter",
            "azurerm_api_management_logger",
            "azurerm_api_management_named_value",
            "azurerm_api_management_openid_connect_provider",
            "azurerm_api_management_product",
            "azurerm_api_management_product_api",
            "azurerm_api_management_product_group",
            "azurerm_api_management_product_policy",
            "azurerm_api_management_property",
            "azurerm_api_management_subscription",
            "azurerm_api_management_user",
            "azurerm_analysis_services_server",
            "azurerm_app_configuration",
            "azurerm_app_service",
            "azurerm_app_service_active_slot",
            "azurerm_app_service_certificate",
            "azurerm_app_service_certificate_order",
            "azurerm_app_service_custom_hostname_binding",
            "azurerm_app_service_environment",
            "azurerm_app_service_hybrid_connection",
            "azurerm_app_service_plan",
            "azurerm_app_service_slot",
            "azurerm_app_service_slot_virtual_network_swift_connection",
            "azurerm_app_service_source_control_token",
            "azurerm_app_service_virtual_network_swift_connection",
            "azurerm_function_app",
            "azurerm_function_app_slot",
            "azurerm_application_insights",
            "azurerm_application_insights_analytics_item",
            "azurerm_application_insights_api_key",
            "azurerm_application_insights_web_test",
            "azurerm_role_assignment",
            "azurerm_role_definition",
            "azurerm_user_assigned_identity",
            "azurerm_automation_account",
            "azurerm_automation_certificate",
            "azurerm_automation_connection",
            "azurerm_automation_connection_certificate",
            "azurerm_automation_connection_classic_certificate",
            "azurerm_automation_connection_service_principal",
            "azurerm_automation_credential",
            "azurerm_automation_dsc_configuration",
            "azurerm_automation_dsc_nodeconfiguration",
            "azurerm_automation_job_schedule",
            "azurerm_automation_module",
            "azurerm_automation_runbook",
            "azurerm_automation_schedule",
            "azurerm_automation_variable_bool",
            "azurerm_automation_variable_datetime",
            "azurerm_automation_variable_int",
            "azurerm_automation_variable_string",
            "azurerm_resource_group",
            "azurerm_batch_account",
            "azurerm_batch_application",
            "azurerm_batch_certificate",
            "azurerm_batch_pool",
            "azurerm_blueprint_assignment",
            "azurerm_bot_channel_directline",
            "azurerm_bot_channel_email",
            "azurerm_bot_channel_ms_teams",
            "azurerm_bot_channel_slack",
            "azurerm_bot_channels_registration",
            "azurerm_bot_connection",
            "azurerm_bot_web_app",
            "azurerm_cdn_endpoint",
            "azurerm_cdn_profile",
            "azurerm_cognitive_account",
            "azurerm_availability_set",
            "azurerm_dedicated_host",
            "azurerm_dedicated_host_group",
            "azurerm_disk_encryption_set",
            "azurerm_image",
            "azurerm_linux_virtual_machine",
            "azurerm_linux_virtual_machine_scale_set",
            "azurerm_managed_disk",
            "azurerm_marketplace_agreement",
            "azurerm_orchestrated_virtual_machine_scale_set",
            "azurerm_proximity_placement_group",
            "azurerm_shared_image",
            "azurerm_shared_image_gallery",
            "azurerm_shared_image_version",
            "azurerm_snapshot",
            "azurerm_virtual_machine",
            "azurerm_virtual_machine_data_disk_attachment",
            "azurerm_virtual_machine_extension",
            "azurerm_virtual_machine_scale_set",
            "azurerm_virtual_machine_scale_set_extension",
            "azurerm_windows_virtual_machine",
            "azurerm_windows_virtual_machine_scale_set",
            "azurerm_container_group",
            "azurerm_container_registry",
            "azurerm_container_registry_webhook",
            "azurerm_kubernetes_cluster",
            "azurerm_kubernetes_cluster_node_pool",
            "azurerm_cosmosdb_account",
            "azurerm_cosmosdb_cassandra_keyspace",
            "azurerm_cosmosdb_gremlin_database",
            "azurerm_cosmosdb_gremlin_graph",
            "azurerm_cosmosdb_mongo_collection",
            "azurerm_cosmosdb_mongo_database",
            "azurerm_cosmosdb_sql_container",
            "azurerm_cosmosdb_sql_database",
            "azurerm_cosmosdb_table",
            "azurerm_cost_management_export_resource_group",
            "azurerm_custom_provider",
            "azurerm_dns_a_record",
            "azurerm_dns_aaaa_record",
            "azurerm_dns_caa_record",
            "azurerm_dns_cname_record",
            "azurerm_dns_mx_record",
            "azurerm_dns_ns_record",
            "azurerm_dns_ptr_record",
            "azurerm_dns_srv_record",
            "azurerm_dns_txt_record",
            "azurerm_dns_zone",
            "azurerm_kusto_attached_database_configuration",
            "azurerm_kusto_cluster",
            "azurerm_kusto_cluster_customer_managed_key",
            "azurerm_kusto_cluster_principal_assignment",
            "azurerm_kusto_database",
            "azurerm_kusto_database_principal",
            "azurerm_kusto_database_principal_assignment",
            "azurerm_kusto_eventhub_data_connection",
            "azurerm_data_factory",
            "azurerm_data_factory_dataset_azure_blob",
            "azurerm_data_factory_dataset_cosmosdb_sqlapi",
            "azurerm_data_factory_dataset_delimited_text",
            "azurerm_data_factory_dataset_http",
            "azurerm_data_factory_dataset_json",
            "azurerm_data_factory_dataset_mysql",
            "azurerm_data_factory_dataset_postgresql",
            "azurerm_data_factory_dataset_sql_server_table",
            "azurerm_data_factory_integration_runtime_managed",
            "azurerm_data_factory_integration_runtime_self_hosted",
            "azurerm_data_factory_linked_service_azure_blob_storage",
            "azurerm_data_factory_linked_service_azure_file_storage",
            "azurerm_data_factory_linked_service_azure_function",
            "azurerm_data_factory_linked_service_cosmosdb",
            "azurerm_data_factory_linked_service_data_lake_storage_gen2",
            "azurerm_data_factory_linked_service_key_vault",
            "azurerm_data_factory_linked_service_mysql",
            "azurerm_data_factory_linked_service_postgresql",
            "azurerm_data_factory_linked_service_sftp",
            "azurerm_data_factory_linked_service_sql_server",
            "azurerm_data_factory_linked_service_web",
            "azurerm_data_factory_pipeline",
            "azurerm_data_factory_trigger_schedule",
            "azurerm_data_lake_analytics_account",
            "azurerm_data_lake_analytics_firewall_rule",
            "azurerm_data_lake_store",
            "azurerm_data_lake_store_file",
            "azurerm_data_lake_store_firewall_rule",
            "azurerm_data_share",
            "azurerm_data_share_account",
            "azurerm_data_share_dataset_blob_storage",
            "azurerm_data_share_dataset_data_lake_gen1",
            "azurerm_mariadb_configuration",
            "azurerm_mariadb_database",
            "azurerm_mariadb_firewall_rule",
            "azurerm_mariadb_server",
            "azurerm_mariadb_virtual_network_rule",
            "azurerm_mssql_database",
            "azurerm_mssql_database_vulnerability_assessment_rule_baseline",
            "azurerm_mssql_elasticpool",
            "azurerm_mssql_server",
            "azurerm_mssql_server_security_alert_policy",
            "azurerm_mssql_server_vulnerability_assessment",
            "azurerm_mssql_virtual_machine",
            "azurerm_mysql_active_directory_administrator",
            "azurerm_mysql_configuration",
            "azurerm_mysql_database",
            "azurerm_mysql_firewall_rule",
            "azurerm_mysql_server",
            "azurerm_mysql_virtual_network_rule",
            "azurerm_postgresql_active_directory_administrator",
            "azurerm_postgresql_configuration",
            "azurerm_postgresql_database",
            "azurerm_postgresql_firewall_rule",
            "azurerm_postgresql_server",
            "azurerm_postgresql_virtual_network_rule",
            "azurerm_sql_active_directory_administrator",
            "azurerm_sql_database",
            "azurerm_sql_elasticpool",
            "azurerm_sql_failover_group",
            "azurerm_sql_firewall_rule",
            "azurerm_sql_server",
            "azurerm_sql_virtual_network_rule",
            "azurerm_database_migration_project",
            "azurerm_database_migration_service",
            "azurerm_databricks_workspace",
            "azurerm_dev_test_global_vm_shutdown_schedule",
            "azurerm_dev_test_lab",
            "azurerm_dev_test_linux_virtual_machine",
            "azurerm_dev_test_policy",
            "azurerm_dev_test_schedule",
            "azurerm_dev_test_virtual_network",
            "azurerm_dev_test_windows_virtual_machine",
            "azurerm_devspace_controller",
            "azurerm_hdinsight_hadoop_cluster",
            "azurerm_hdinsight_hbase_cluster",
            "azurerm_hdinsight_interactive_query_cluster",
            "azurerm_hdinsight_kafka_cluster",
            "azurerm_hdinsight_ml_services_cluster",
            "azurerm_hdinsight_rserver_cluster",
            "azurerm_hdinsight_spark_cluster",
            "azurerm_hdinsight_storm_cluster",
            "azurerm_dedicated_hardware_security_module",
            "azurerm_healthcare_service",
            "azurerm_iotcentral_application",
            "azurerm_iothub",
            "azurerm_iothub_consumer_group",
            "azurerm_iothub_dps",
            "azurerm_iothub_dps_certificate",
            "azurerm_iothub_dps_shared_access_policy",
            "azurerm_iothub_shared_access_policy",
            "azurerm_key_vault",
            "azurerm_key_vault_access_policy",
            "azurerm_key_vault_certificate",
            "azurerm_key_vault_certificate_issuer",
            "azurerm_key_vault_key",
            "azurerm_key_vault_secret",
            "azurerm_lb",
            "azurerm_lb_backend_address_pool",
            "azurerm_lb_nat_pool",
            "azurerm_lb_nat_rule",
            "azurerm_lb_outbound_rule",
            "azurerm_lb_probe",
            "azurerm_lb_rule",
            "azurerm_log_analytics_datasource_windows_event",
            "azurerm_log_analytics_datasource_windows_performance_counter",
            "azurerm_log_analytics_linked_service",
            "azurerm_log_analytics_solution",
            "azurerm_log_analytics_workspace",
            "azurerm_logic_app_action_custom",
            "azurerm_logic_app_action_http",
            "azurerm_logic_app_integration_account",
            "azurerm_logic_app_trigger_custom",
            "azurerm_logic_app_trigger_http_request",
            "azurerm_logic_app_trigger_recurrence",
            "azurerm_logic_app_workflow",
            "azurerm_machine_learning_workspace",
            "azurerm_maintenance_assignment_dedicated_host",
            "azurerm_maintenance_assignment_virtual_machine",
            "azurerm_maintenance_configuration",
            "azurerm_managed_application",
            "azurerm_managed_application_definition",
            "azurerm_management_group",
            "azurerm_management_lock",
            "azurerm_maps_account",
            "azurerm_media_services_account",
            "azurerm_eventgrid_domain",
            "azurerm_eventgrid_domain_topic",
            "azurerm_eventgrid_event_subscription",
            "azurerm_eventgrid_topic",
            "azurerm_eventhub",
            "azurerm_eventhub_authorization_rule",
            "azurerm_eventhub_cluster",
            "azurerm_eventhub_consumer_group",
            "azurerm_eventhub_namespace",
            "azurerm_eventhub_namespace_authorization_rule",
            "azurerm_eventhub_namespace_disaster_recovery_config",
            "azurerm_iothub_endpoint_eventhub",
            "azurerm_iothub_endpoint_servicebus_queue",
            "azurerm_iothub_endpoint_servicebus_topic",
            "azurerm_iothub_endpoint_storage_container",
            "azurerm_iothub_fallback_route",
            "azurerm_iothub_route",
            "azurerm_notification_hub",
            "azurerm_notification_hub_authorization_rule",
            "azurerm_notification_hub_namespace",
            "azurerm_relay_hybrid_connection",
            "azurerm_relay_namespace",
            "azurerm_servicebus_namespace",
            "azurerm_servicebus_namespace_authorization_rule",
            "azurerm_servicebus_namespace_network_rule_set",
            "azurerm_servicebus_queue",
            "azurerm_servicebus_queue_authorization_rule",
            "azurerm_servicebus_subscription",
            "azurerm_servicebus_subscription_rule",
            "azurerm_servicebus_topic",
            "azurerm_servicebus_topic_authorization_rule",
            "azurerm_signalr_service",
            "azurerm_spatial_anchors_account",
            "azurerm_monitor_action_group",
            "azurerm_monitor_action_rule_action_group",
            "azurerm_monitor_action_rule_suppression",
            "azurerm_monitor_activity_log_alert",
            "azurerm_monitor_autoscale_setting",
            "azurerm_monitor_diagnostic_setting",
            "azurerm_monitor_log_profile",
            "azurerm_monitor_metric_alert",
            "azurerm_monitor_scheduled_query_rules_alert",
            "azurerm_monitor_scheduled_query_rules_log",
            "azurerm_netapp_account",
            "azurerm_netapp_pool",
            "azurerm_netapp_snapshot",
            "azurerm_netapp_volume",
            "azurerm_application_gateway",
            "azurerm_application_security_group",
            "azurerm_bastion_host",
            "azurerm_express_route_circuit",
            "azurerm_express_route_circuit_authorization",
            "azurerm_express_route_circuit_peering",
            "azurerm_express_route_gateway",
            "azurerm_firewall",
            "azurerm_firewall_application_rule_collection",
            "azurerm_firewall_nat_rule_collection",
            "azurerm_firewall_network_rule_collection",
            "azurerm_frontdoor",
            "azurerm_frontdoor_custom_https_configuration",
            "azurerm_frontdoor_firewall_policy",
            "azurerm_local_network_gateway",
            "azurerm_nat_gateway",
            "azurerm_nat_gateway_public_ip_association",
            "azurerm_network_ddos_protection_plan",
            "azurerm_network_interface",
            "azurerm_network_interface_application_gateway_backend_address_pool_association",
            "azurerm_network_interface_application_security_group_association",
            "azurerm_network_interface_backend_address_pool_association",
            "azurerm_network_interface_nat_rule_association",
            "azurerm_network_interface_security_group_association",
            "azurerm_network_packet_capture",
            "azurerm_network_profile",
            "azurerm_network_security_group",
            "azurerm_network_security_rule",
            "azurerm_network_watcher",
            "azurerm_network_watcher_flow_log",
            "azurerm_packet_capture",
            "azurerm_point_to_site_vpn_gateway",
            "azurerm_private_endpoint",
            "azurerm_private_link_service",
            "azurerm_public_ip",
            "azurerm_public_ip_prefix",
            "azurerm_route",
            "azurerm_route_filter",
            "azurerm_route_table",
            "azurerm_traffic_manager_endpoint",
            "azurerm_traffic_manager_profile",
            "azurerm_virtual_hub",
            "azurerm_virtual_hub_connection",
            "azurerm_virtual_network",
            "azurerm_virtual_network_gateway",
            "azurerm_virtual_network_gateway_connection",
            "azurerm_virtual_network_peering",
            "azurerm_virtual_wan",
            "azurerm_vpn_gateway",
            "azurerm_vpn_server_configuration",
            "azurerm_web_application_firewall_policy",
            "azurerm_policy_assignment",
            "azurerm_policy_definition",
            "azurerm_policy_remediation",
            "azurerm_policy_set_definition",
            "azurerm_dashboard",
            "azurerm_powerbi_embedded",
            "azurerm_private_dns_a_record",
            "azurerm_private_dns_aaaa_record",
            "azurerm_private_dns_cname_record",
            "azurerm_private_dns_mx_record",
            "azurerm_private_dns_ptr_record",
            "azurerm_private_dns_srv_record",
            "azurerm_private_dns_txt_record",
            "azurerm_private_dns_zone",
            "azurerm_private_dns_zone_virtual_network_link",
            "azurerm_backup_container_storage_account",
            "azurerm_backup_policy_file_share",
            "azurerm_backup_policy_vm",
            "azurerm_backup_protected_file_share",
            "azurerm_backup_protected_vm",
            "azurerm_recovery_services_vault",
            "azurerm_site_recovery_fabric",
            "azurerm_site_recovery_network_mapping",
            "azurerm_site_recovery_protection_container",
            "azurerm_site_recovery_protection_container_mapping",
            "azurerm_site_recovery_replicated_vm",
            "azurerm_site_recovery_replication_policy",
            "azurerm_redis_cache",
            "azurerm_redis_firewall_rule",
            "azurerm_search_service",
            "azurerm_advanced_threat_protection",
            "azurerm_security_center_contact",
            "azurerm_security_center_subscription_pricing",
            "azurerm_security_center_workspace",
            "azurerm_sentinel_alert_rule_ms_security_incident",
            "azurerm_sentinel_alert_rule_scheduled",
            "azurerm_service_fabric_cluster",
            "azurerm_spring_cloud_app",
            "azurerm_spring_cloud_service",
            "azurerm_hpc_cache",
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
