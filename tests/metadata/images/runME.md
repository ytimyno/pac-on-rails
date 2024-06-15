## Run
checkov -d *path: dockerfile directory, containerfiles* --external-checks-dir *path custom checks, checks/metadata/images* --framework dockerfile -c CKV_DOCKER_LABEL_CHECK

## Customise

Customise with *policy/metadata/images/policy.json* as needed and copy it. Else, it will use a pre-def set of values. 

I would create a script for this. To customise a file, it needs to be in the dir where checkov runs from (see future work).

## Overall Things to Do:

- Combine Checks: Explore combining Cloud-Native (CN) and traditional IaC checks into a unified metadata validation approach.
- Customize Input Paths: Customize the path to input files (policy.json) for higher flexibility.