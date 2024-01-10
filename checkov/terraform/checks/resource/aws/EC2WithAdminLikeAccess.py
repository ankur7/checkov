import re

from typing import List, Union

from igraph import VertexSeq

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import flatten, is_public_ip,\
    get_sg_ingress_attributes, is_tagged_for_exceptions, contains_exception_tag

AWS = 'aws'

AWS_INSTANCE = 'aws_instance'
AWS_LAUNCH_TEMPLATE = 'aws_launch_template'
AWS_LAUNCH_CONFIGURATION = 'aws_launch_configuration'
AWS_IAM_ROLE = 'aws_iam_role'
AWS_IAM_ROLE_POLICY = 'aws_iam_role_policy'
AWS_IAM_ROLE_POLICY_ATTACHMENT = 'aws_iam_role_policy_attachment'  # AWS managed policies
AWS_SECURITY_GROUP = 'aws_security_group'


def get_actions_from_statement(statement):
    """Given a statement dictionary, create
    a list of the actions contained within
    Args:
        statement (dict): The statement to be evaluated
    Returns:
        list: The list of actions
    """

    actions_list = []
    # We only want to evaluate policies that have Effect = "Allow"
    if statement.get("Effect") == "Deny":
        # logging.warning("Deny effect found in policy")
        return actions_list
    elif statement.get("NotAction") is not None:
        # logging.warning("Allow - NotAction statement found in policy")
        actions_list.append("*")
    else:
        action_clause = statement.get("Action")
        if not action_clause:
            # logging.debug("No actions contained in statement")
            return actions_list
        # Action = "s3:GetObject"
        if isinstance(action_clause, str):
            actions_list.append(action_clause)
        # Action = ["s3:GetObject", "s3:ListBuckets"]
        elif isinstance(action_clause, list):
            actions_list.extend(action_clause)
        # else:
        #     logging.error("Unknown error: The 'Action' is neither a list nor a string")

    return actions_list


def get_admin_actions(policy):
    """Takes in a policy and returns the list
    of admin-like actions that it allows
    Args:
        policy (dict): The policy to be evaluated
    Returns:
        list: The list of admin-like actions
    """

    # fail safe
    actions = []

    if isinstance(policy["Statement"], dict):
        actions = get_actions_from_statement(policy["Statement"])
    elif isinstance(policy["Statement"], list):
        for statement in policy["Statement"]:
            actions.extend(get_actions_from_statement(statement))
    # else:
    #     logging.error("Unknown error: The 'Statement' is neither a dict nor a list")

    admin_actions = []

    for action in actions:
        # strings are immutable so doing this
        # won't modify items in the list
        action = action.lower()

        # list of Admin-like scenarios we are looking for
        if action == "*":
            # "Action": "*"
            # logging.debug("All actions are allowed by this policy: %s", action)
            admin_actions.append(action)
        elif action.startswith("iam"):
            # "Action": "iam:PassRole"
            # logging.debug("IAM actions are allowed by this policy: %s", action)
            admin_actions.append(action)
        else:
            if action in [
                "ec2:runinstances",
                "ec2:terminateinstances",
                "glue:updatedevendpoint",
                "lambda:updatefunctioncode",
            ]:
                # action allows compute level control
                # logging.debug(f"This policy allows compute level control: {action}")
                admin_actions.append(action)
            else:
                # "Action": "s3:*"
                _, service_action = action.split(":")
                if service_action == "*":
                    # logging.debug(f"This policy allows {action}")
                    admin_actions.append(action)

    return admin_actions


def _is_ec2_instance_publicly_accessible(graph, resource_instance: VertexSeq, resource_instance_type: str) -> Union[bool, None]:
    """
    Check if the EC2 instance is publicly accessible based on its connected security groups.

    Parameters:
    - graph (Graph): The igraph Graph object.
    - aws_instance (VertexSeq): VertexSeq for the EC2 Instance.

    Returns:
    - Union[bool, None]: True if the EC2 instance is publicly accessible, None otherwise.
    """

    connected_security_groups = [neighbor for neighbor in graph.vs[resource_instance.index].neighbors() if
                                 neighbor['resource_type'] == AWS_SECURITY_GROUP]

    for security_group in connected_security_groups:
        security_group_attributes = security_group.attributes()
        security_group_name = security_group_attributes['attr']['block_name_'].split('.')[1]
        ingress_list = security_group_attributes['attr']['config_'][AWS_SECURITY_GROUP][security_group_name].get('ingress')

        if not ingress_list:
            continue  # no ingress_list, cannot check

        ingress_list = flatten(ingress_list)

        for ingress in ingress_list:
            ingress_attributes = get_sg_ingress_attributes(ingress)

            cidr_blocks = ingress_attributes.get('cidr_blocks', None)
            # from_port = ingress_attributes.get('from_port', None)
            # to_port = ingress_attributes.get('to_port', None)
            # protocol = ingress_attributes.get('protocol', None)

            if not cidr_blocks:
                continue

            for ip_or_cidr in cidr_blocks:
                if is_public_ip(ip_or_cidr):
                    return True
                    # if is_tagged_for_exceptions(resource_instance, resource_instance_type, from_port, to_port, protocol):
                    #     continue
                    # else:
                    #     return True


class EC2WithAdminLikeAccess(BaseResourceCheck):

    def __init__(self):
        name = "Prevent internet accessible EC2 instances with admin-like profiles"
        id = "CKV_AWS_IDENTITY_0004"
        supported_resources = [AWS_INSTANCE, AWS_LAUNCH_TEMPLATE, AWS_LAUNCH_CONFIGURATION]
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        # vertices = graph.vs
        # edges = graph.es
        # for edge in edges:
        #     print(f"Edge {edge.index}: {edge.tuple}")
        #
        # for ver in graph.vs:
        #     address = ver['attr'].get('__address__')
        #     if address:
        #         pass
        #         # print(f"Ver Address: {address}.\nCon Address: {conf['__address__']} ")
        #     else:
        #         print(ver['attr'].get('block_type_'))
        #         # print('\n')
        #         # print(ver['attr'])
        #         # print(f"BlockName: {ver['attr'].get('block_name_')}")
        #         # print('\n')

        # aws_instance_list = vertices.select(resource_type=AWS_INSTANCE)
        aws_instance_list = graph.vs.select(lambda vertex: vertex['attr'].get('__address__') == conf["__address__"] and (
                                                           vertex["resource_type"] == AWS_INSTANCE or
                                                           vertex["resource_type"] == AWS_LAUNCH_TEMPLATE or
                                                           vertex["resource_type"] == AWS_LAUNCH_CONFIGURATION
                                            ))
        # todo aj move launch template and launch configuration. use it only when it is connected to an auto scaling group
        for aws_instance in aws_instance_list:

            # First check if aws_instance is publicly accessible
            is_publicly_accessible = _is_ec2_instance_publicly_accessible(graph, aws_instance, AWS_INSTANCE)

            if not is_publicly_accessible:
                continue

            # EC2 instance is publicly accessible, now check admin like policies

            connected_iam_roles = [neighbor for neighbor in graph.vs[aws_instance.index].neighbors() if
                                   neighbor['resource_type'] == AWS_IAM_ROLE]

            for iam_role in connected_iam_roles:
                connected_iam_custom_policies = [neighbor for neighbor in graph.vs[iam_role.index].neighbors() if
                                                 neighbor['resource_type'] == AWS_IAM_ROLE_POLICY]

                # For iam policy, we need to first describe the policy then check it's JSON. Cannot be done without making call.to AWS account
                # Cannot be done
                connected_iam_aws_policies = [neighbor for neighbor in graph.vs[iam_role.index].neighbors() if
                                              neighbor['resource_type'] == AWS_IAM_ROLE_POLICY_ATTACHMENT]

                for policy in connected_iam_custom_policies:
                    policy_attributes = policy.attributes()
                    policy_name = policy_attributes['attr']['block_name_'].split('.')[1]
                    policy_content_json = policy_attributes['attr']['config_']['aws_iam_role_policy'][policy_name][
                        'policy']
                    has_admin_actions = get_admin_actions(
                        policy_content_json[0])  # todo aj check if more than 1 item can be present in the dict
                    if has_admin_actions:
                        if contains_exception_tag(aws_instance, AWS_INSTANCE, tag_key="AllowPublicAdminLike", tag_value=True):
                            continue
                        else:
                            return CheckResult.FAILED

        return result

    def get_evaluated_keys(self) -> List[str]:
        return ['user_data']


check = EC2WithAdminLikeAccess()
