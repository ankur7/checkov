from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

AWS_IAM_USER = 'aws_iam_user'
AWS_IAM_USER_LOGIN_PROFILE = 'aws_iam_user_login_profile'


class IAMUserPasswordNotAllowed(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Block use of passwords for IAM Users"
        id = "CKV_AWS_IDENTITY_0001"
        supported_resources = ('aws_iam_user',)
        categories = (CheckCategories.IAM,)
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        aws_iam_user_list = graph.vs.select(lambda vertex: vertex["resource_type"] == AWS_IAM_USER)

        for aws_iam_user in aws_iam_user_list:
            aws_iam_user_login_profile_list = [neighbor for neighbor in graph.vs[aws_iam_user.index].neighbors() if
                                               neighbor['resource_type'] == AWS_IAM_USER_LOGIN_PROFILE]
            if aws_iam_user_login_profile_list:
                return CheckResult.FAILED

        return result


check = IAMUserPasswordNotAllowed()
