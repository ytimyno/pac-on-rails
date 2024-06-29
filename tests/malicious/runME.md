### Customise
No customisation needed. Just a proof of concept on why you should not use extra checks from untrusted/unknown repositories.

## Run - DONT

checkov -d . --external-checks-dir checks/malicious/ -c CKV_COOL_MALI_CHECK
checkov -d . --external-checks-git https://github.com/ytimyno/pac-on-rails.git//checks/malicious -c CKV_COOL_MALI_CHECK