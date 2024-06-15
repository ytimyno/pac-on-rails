### Customise
Customise with policy.json as needed. Else, it will use a pre-def set of values. To customise a file, it needs to be in the dir where checkov runs from (see future work).

## Run

### Container Images
checkov -d *path: dockerfile directory, i.e.: containerfiles/* --external-checks-dir *path to custom checks, i.e.: checks/metadata/images* --framework dockerfile -c CKV_DOCKER_LABEL_CHECK

## Future Work

- Refine IaC Resources: Review and reduce the list of resources (supported_resources) that support tags/labels.
- Combine Checks: Explore combining Cloud-Native (CN) and traditional IaC checks into a unified metadata validation approach.
- Customize Input Paths: Customize the path to input files (policy.json, cloud_specific_configurations.json) for higher flexibility.