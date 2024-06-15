# pac-on-rails
Mini project to automates Policy as Code (PaC) and guardrails to ensure adherence to organizational policies.
Supports Traditional IaC Infrastructure and Cloud Native.

## Engine 

### Container Images

This repository leverages Checkov to perform checks against container images' labelling policies. The engine ensures compliance with the specified policy (see customisation section).

### Traditional IaC Infrastructure

This repository leverages Checkov to perform checks against infrastructure metadata policies (Terraform-defined). The engine ensures compliance with the specified policy (see customisation section).

#### Supported Cloud Providers

- **AWS**
- **Azure**
- **Google Cloud Platform (GCP)**

#### Cloud-specific Configuration

Each cloud provider has its own configuration section within the engine. Below are details specific to each cloud:
- Resources to check for metadata pairs (Azure). Modify tag_paths as necessary. Azure uses "tags" for metadata but other providers may use "labels".
- **Supported Resource Types**: Lists of Cloud/specific resource types where tagging policies are enforced.


## Metadata Policy Format (Container Images & Traditional IaC Infrastructure)

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

### Customise
Customise with cloud_specific_configurations.json and policy.json as needed. Else, it will use a pre-def set of values. To customise a file, it needs to be in the dir where checkov runs from (see future work).

## Run

### Container Images
checkov -d *path: dockerfile directory, i.e.: containerfiles/* --external-checks-dir *path to custom checks, i.e.: checks/metadata/images* --framework dockerfile -c CKV_DOCKER_LABEL_CHECK


### Traditional IaC Infrastructure
checkov -d *path: dockerfile directory, i.e.: terraform/* --external-checks-dir *path to custom checks, i.e.: checks/metadata/infrastructure* -c CKV_TF_METADATA_CHECK 


## Future Work

- Refine IaC Resources: Review and reduce the list of resources (supported_resources) that support tags/labels.
- Combine Checks: Explore combining Cloud-Native (CN) and traditional IaC checks into a unified metadata validation approach.
- Customize Input Paths: Customize the path to input files (policy.json, cloud_specific_configurations.json) for higher flexibility.

## Contact

For questions or feedback, please contact [ytimyno@gmail.com](mailto:ytimyno@gmail.com).
