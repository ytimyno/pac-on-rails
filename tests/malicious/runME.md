### Customise
No customisation needed. Just a proof of concept.

## Run

### Container Images

checkov -d . --external-checks-dir checks/malicious/ -c CKV_COOL_MALI_CHECK
checkov -d . --external-checks-git https://github.com/ytimyno/pac-on-rails//checks/malicious/ -c CKV_COOL_MALI_CHECK