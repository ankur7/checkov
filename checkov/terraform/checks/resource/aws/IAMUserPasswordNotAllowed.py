from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import filter_nodes_by_resource_type, CustomVertex, \
    find_neighbors_with_resource_type

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
        """
        Looks for password login profile for IAM users
        In this check we are looking for the presence of a password login profile: aws_iam_user_login_profile
        If it exists then it means that Console password is present for that iam user and the check fails
        :param conf: aws_iam_user configuration
        :return: <CheckResult>
        """
        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        # aws_iam_user_list = graph.vs.select(lambda vertex: vertex['attr'].get('__address__') == str(conf["__address__"]) and (
        #                                                    vertex["resource_type"] == AWS_IAM_USER)
        #                                     )

        aws_iam_user_list: list[CustomVertex] = filter_nodes_by_resource_type(graph, str(conf["__address__"]), [AWS_IAM_USER])

        for custom_vertex in aws_iam_user_list:
            aws_iam_user_login_profile_list: list[CustomVertex] = find_neighbors_with_resource_type(graph, custom_vertex, AWS_IAM_USER_LOGIN_PROFILE)
            # aws_iam_user_login_profile_list = [neighbor for neighbor in graph.vs[aws_iam_user.index].neighbors() if
            #                                    neighbor['resource_type'] == AWS_IAM_USER_LOGIN_PROFILE]
            if aws_iam_user_login_profile_list:
                return CheckResult.FAILED

        return result


check = IAMUserPasswordNotAllowed()
