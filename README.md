# pac-on-rails
Mini project to automate Policy as Code (PaC) and guardrails to ensure adherence to tagging/labelling policies.
Supports Traditional IaC Infrastructure and Container Images.

## Policy Engine 

### Container Images

This repository leverages Checkov to perform checks against container images' labelling policies. The engine ensures compliance with the specified policy (see customisation section).

### Traditional IaC Infrastructure

This repository leverages Checkov to perform checks against infrastructure metadata policies (Terraform-defined). The engine ensures compliance with the specified policy (see customisation section).

#### Supported Cloud Providers

- **AWS**
- **Azure**
- **Google Cloud Platform (GCP)**

#### Cloud-specific Configuration

Each cloud provider has its own configuration section within the engine. The JSON file lists specific configurations to take, according to the CSP. This is here, not only, but also because CSPs use different terms to refer to the same thing.
- *tag_paths*: This lists the paths to check for metadata (within Terraform, for the specific provider). Easy mode, specify one tag path per CSP. Medium mode: Specify multiple paths. Hardcore, specify multiple paths and sub.paths (see example in [cloud_specific_configurations.json](./policy/metadata/infrastructure/cloud_specific_configurations.json)). Note specifying te«he capability to specify sub.paths is quite tigthly coupled with a few test examples. Hence it is fragile. Easy mode recommended.
- *tag_paths_strict*: If multiple paths are specified, they all will be checked. If tag_paths_strict is True, all of the paths must be present in the resource and must comply with the policy. See the section [metadata policy format](#metadata-policy-format). Copy an example from [policy.json](./policy/metadata/infrastructure/policy.json) into you running directory, as explained in the [run section](#run).
- *Supported Resource Types*: Lists of Cloud/specific resource types where tagging policies are enforced. See [future work](#future-work).


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

## Security Advisory - Before Running
To use extra checks with Checkov CLI tool, we can:
1. Specifying a directory with the extra checks' code, or
2. Specifying a Git repo that contains the extra checks' code.

I'd recommend one. And if you ask me about number two, I would always do it from a private and/or very well scrutinised git repo. 

Checkov checks are really just running extra code: With custom Python checks, it's running custom Python scripts. With custom Python checks from a remote repo, it's running (potentially dangerous) custom Python scripts from a remote repo. 

I done a simple PoC that creates a user, creates a files and runs bash commands. I installed an openssh server in the machine running Checkov and then was able to connect to it, using the created user (obviously, installs and user creation requires sudo, and connection may be harder with FW rules in place, but possibilities are endless, especially on the integrity side, where we can mess with the FS).

    1. Try to SSH (not running, so I have connection refused)
    2. Run malicious check from remote git repo
    3. SSH with the newly created user

Sky is the limit here. With or without root privileges, you can leave a mark. So, my advice is to be very careful when running random people's checks. This is true with any (especially open source) tool. That said, I feel the official Checkov documentation and GitHub pages could be clearer. The only place I could find that lightly touches on this is a small paragraph on best practices in the GitHub page (https://github.com/bridgecrewio/checkov?tab=readme-ov-file#configuration-using-a-config-file).


## Run

### Container Images
checkov -d *containerfile_dir/* --external-checks-dir *checks/metadata/images* --framework dockerfile -c CKV_DOCKER_LABEL_CHECK


### Traditional IaC Infrastructure
checkov -d *terraform_dir/* --external-checks-dir *checks/metadata/infrastructure* -c CKV_TF_METADATA_CHECK 


## Future Work

- Refine IaC Resources: Review and reduce the list of resources (supported_resources) that support tags/labels.
- Combine Checks: Explore combining Cloud-Native (CN) and traditional IaC checks into a unified metadata validation approach.
- Customize Input Paths: Customize the path to input files (policy.json, cloud_specific_configurations.json) for higher flexibility.

## Contact

For questions or feedback, please contact [ytimyno@gmail.com](mailto:ytimyno@gmail.com).
