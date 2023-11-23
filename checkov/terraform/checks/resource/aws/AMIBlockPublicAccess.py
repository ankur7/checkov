from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class AMIBlockPublicAccess(BaseResourceCheck):
    def __init__(self):
        name = "Ensure AMIs are never shared with the public"  # todo aj later  or AWS accounts not owned by Adobe
        id = "CKV_AWS_COMPUTE_0002"
        supported_resources = ['aws_ami', 'aws_ami_launch_permission']
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf) -> CheckResult:

        if conf.get('launch_permission'):

            # 'user_ids' is mandatory inside a launch_permission
            user_ids = conf['launch_permission'][0].get('user_ids', None)

            if user_ids:
                user_ids = user_ids[0]  # not sure why it makes list of list
            for user_id in user_ids:
                if user_id.lower() == 'all':
                    return CheckResult.FAILED

        if conf.get('account_id'):  # through aws_ami_launch_permission todo aj handle this better
            if conf['account_id'][0].lower() == 'all':
                return CheckResult.FAILED

        return CheckResult.PASSED


check = AMIBlockPublicAccess()
