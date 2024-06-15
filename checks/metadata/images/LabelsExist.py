from __future__ import annotations

from typing import TYPE_CHECKING, List
import re, json, os

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck

if TYPE_CHECKING:
    from dockerfile_parse.parser import _Instruction


class LabelCheck(BaseDockerfileCheck):

    def __init__(self, labels_to_check: List[dict]) -> None:
        name = "Ensure that specified LABEL instructions have been added to container images"
        id = "CKV_DOCKER_LABEL_CHECK"
        supported_instructions = ("*",)
        categories = (CheckCategories.NETWORKING,)
        self.labels_to_check = labels_to_check
        super().__init__(name=name, id=id, categories=categories, supported_instructions=supported_instructions)

    def scan_resource_conf(self, conf: dict[str, list[_Instruction]]) -> Tuple[CheckResult, Union[list[_Instruction], None]]:  # type:ignore[override]  # special wildcard behaviour
        
        
        # because we're looking for any use of "" or '' or nothing at all, the resulting matches will have 4 elements 
        label_pattern = re.compile(r'([\w\.\-]+)=(?:"([^"]+)"|\'([^\']+)\'|([^\'"][^ ]*))')
        label_pairs = {}

        open("scan_resource_labels.log", 'w').close()

        with open("scan_resource_labels.log", '+a') as log_file:

            log_file.write("\nValidating against:\n")
            json.dump(self.labels_to_check, log_file, indent=4)

            if "LABEL" in conf.keys():
                raw_label_instructions = conf['LABEL']
            else:
                self.details.append("No LABEL instruction found")  
                log_file.write("\nNo LABEL instruction found. FAIL\n")

                return CheckResult.FAILED, None
            
            for raw_label_instructions in conf['LABEL']:

                instruction = raw_label_instructions['instruction'] # should be LABEL
                raw_value = raw_label_instructions['value']

                if not isinstance(raw_value, str):
                    continue

                key_value_pairs = label_pattern.findall(raw_value)
                key_value_pairs = [tuple(filter(None, x)) for x in key_value_pairs]

                for match in key_value_pairs:
                    label_pairs[match[0]] = match[1]

        
            for label_to_check_key,label_to_check in self.labels_to_check.items():

                if label_to_check_key not in label_pairs.keys():
                    self.details.append("Label "+label_to_check_key+" is not defined")
                    log_file.write("\nLabel "+label_to_check_key+" is not defined. FAIL\n")              
                    return CheckResult.FAILED, None
                
                allowed_values_pattern = re.compile(r""+label_to_check['allowed_values'])
                if allowed_values_pattern.match(label_pairs[label_to_check_key]):
                    log_file.write("\nLabel "+label_to_check_key+" defined and within allowed values "+label_to_check['allowed_values']+".\n") 
                    continue
                else:
                    self.details.append("Label "+label_to_check_key+" exists but does not match allowed values "+label_to_check['allowed_values'])
                    log_file.write("\nLabel "+label_to_check_key+" exists but does not match allowed values "+label_to_check['allowed_values']+".\nFAIL\n")  
                    return CheckResult.FAILED, None
                
            log_file.write("\nAll labels PASSED validation.\n") 

        return CheckResult.PASSED, None


default_labels = {
    "maintainer": {
        "allowed_values": ".*",
        "version": "1.0",
        "description": "A sample label - Any value accepted"
    }, 
    "maintainer_specific":{
        "allowed_values": "^[\w\.-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$",
        "version": "1.0",
        "description": "A sample label - Specific regex"
    },
    "random_label":{
        "key": "unspecified_random_label",
        "allowed_values": ".*",
        "version": "1.0",
        "description": "A sample label - This will fail"
    }
}

file_name = 'containerfile_labels.json'

if os.path.exists(file_name):
    # If the file exists, open and read the JSON data
    with open(file_name, 'r') as file:
        try:
            labels_to_check = json.load(file)
        except:
            labels_to_check = default_labels
else:
    # If the file doesn't exist, use the default dictionary
    labels_to_check = default_labels



check = LabelCheck(labels_to_check)