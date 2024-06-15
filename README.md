# pac-on-rails
Mini project to automates Policy as Code (PaC) and guardrails to ensure adherence to organizational policies.
Supports Traditional IaC Infrastructure and Cloud Native.

## Engine / Traditional IaC Infrastructure

### Overview

This repository leverages Checkov to enforce tagging policies across multiple cloud providers: AWS, Azure, and GCP. The engine ensures compliance with specified metadata pairs across supported resource types in each cloud platform.

### Supported Cloud Providers

- **AWS**
- **Azure**
- **Google Cloud Platform (GCP)**

### Tagging Policy Format

The tagging policy is defined using JSON format, allowing for flexible customization of metadata pairs and their validation rules.

```json
{
    "maintainer": {
        "allowed_values": ".*",
        "version": "1.0",
        "description": "A sample metadata pair - Any value accepted"
    },
    "maintainer_specific": {
        "allowed_values": "^[\w\.-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$",
        "version": "1.0",
        "description": "A sample metadata pair - Specific regex"
    }
}
```

### Cloud-specific Configuration

Each cloud provider has its own configuration section within the engine. Below are details specific to each cloud:

#### Azure

- Resources to check for metadata pairs (Azure). Modify tag_paths as necessary. Azure uses "tags" for metadata but other providers may use "labels".
- **Supported Resource Types**: Lists of Azure resource types where tagging policies are enforced.

#### AWS

- Resources to check for metadata pairs (AWS). Modify `tag_paths` as necessary. AWS uses "tags" for metadata but other providers may use "labels". 
- **Supported Resource Types**: Lists of AWS resource types where tagging policies are enforced.

#### Google Cloud Platform (GCP)

- Resources to check for metadata pairs (GCP). Modify `tag_paths` as necessary. GCP uses "labels" (but it also uses "tags"!) for metadata.
- **Supported Resource Types**: Lists of GCP resource types where tagging policies are enforced.

## Run

checkov -d terraform/ --external-checks-dir ../../extra_checks -c CKV_TF_METADATA_CHECK 

## Customise

Customise with cloud_specific_configurations.json and policy.json as needed. Else, it will use a pre-def set of values. To customise a file, it needs to be in the dir where checkov runs from (see future work).

## Overall Things to Do:

- Refine IaC Resources: Review and reduce the list of resources (supported_resources) that support tags/labels.
- Combine Checks: Explore combining Cloud-Native (CN) and traditional IaC checks into a unified metadata validation approach.
- Customize Input Paths: Customize the path to input files (policy.json, cloud_specific_configurations.json) for higher flexibility.

## Contact

For questions or feedback, please contact [ytimyno@gmail.com](mailto:ytimyno@gmail.com).
