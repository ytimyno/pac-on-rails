## Run
cd checkov/terraform/extra_checks/extra_test
checkov -d terraform/ --external-checks-dir ../../extra_checks -c CKV_TF_METADATA_CHECK 

## Customise

Customise with *policy/metadata/infrastructure/cloud_specific_configurations.json* and *policy/metadata/infrastructure/policy.json* as needed and copy it. Else, it will use a pre-def set of values. 

I would create a script for this. To customise a file, it needs to be in the dir where checkov runs from (see future work).

## Overall Things to Do:

- Refine IaC Resources: Review and reduce the list of resources (supported_resources) that support tags/labels.
- Combine Checks: Explore combining Cloud-Native (CN) and traditional IaC checks into a unified metadata validation approach.
- Customize Input Paths: Customize the path to input files (policy.json, cloud_specific_configurations.json) for higher flexibility.