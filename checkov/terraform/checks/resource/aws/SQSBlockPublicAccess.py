from typing import Dict, List, Any

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
#
# AWS_SQS_QUEUE = 'aws_sqs_queue'
# AWS_SQS_QUEUE_POLICY = 'aws_sqs_queue_policy'


class SQSBlockPublicAccess(BaseResourceCheck):
    def __init__(self):
        name = "Block access to SQS queues from public"
        id = "CKV_AWS_SERVICE_0005"
        supported_resources = ['aws_sqs_queue_policy']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "policy" in conf.keys():
            policy = conf["policy"][0]
            if type(policy) is dict:
                statement = policy['Statement'][0]
                if type(statement) is dict:
                    if statement['Principal'] == '*':
                        return CheckResult.FAILED
        return CheckResult.PASSED

    def get_evaluated_keys(self) -> List[str]:
        return ['policy']


check = SQSBlockPublicAccess()