from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.secrets import string_has_secrets
from typing import List

AWS = 'aws'

AWS_INSTANCE = 'aws_instance'
AWS_LAUNCH_TEMPLATE = 'aws_launch_template'
AWS_LAUNCH_CONFIGURATION = 'aws_launch_configuration'
AWS_IAM_ROLE = 'aws_iam_role'
AWS_IAM_ROLE_POLICY = 'aws_iam_role_policy'
AWS_IAM_ROLE_POLICY_ATTACHMENT = 'aws_iam_role_policy_attachment'  # AWS managed policies


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


class EC2WithAdminLikeAccess(BaseResourceCheck):

    def __init__(self):
        name = "Prevent internet accessible EC2 instances with admin-like profiles"
        id = "CKV_AWS_CUSTOM_01"
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

        # aws_instance_list = vertices.select(resource_type=AWS_INSTANCE)
        aws_instance_list = graph.vs.select(lambda vertex: vertex["resource_type"] == AWS_INSTANCE or
                                                           vertex["resource_type"] == AWS_LAUNCH_TEMPLATE or
                                                           vertex["resource_type"] == AWS_LAUNCH_CONFIGURATION
                                            )
        for aws_instance in aws_instance_list:
            # all_neighbors_indices = graph.neighbors(aws_instance)
            # all_neighbors_vertices = [vertices[ind] for ind in all_neighbors_indices]
            # connected_iam_roles = [neighbor for neighbor in all_neighbors_vertices if neighbor['resource_type'] == AWS_IAM_ROLE]

            connected_iam_roles = [neighbor for neighbor in graph.vs[aws_instance.index].neighbors() if
                                   neighbor['resource_type'] == AWS_IAM_ROLE]

            for iam_role in connected_iam_roles:
                connected_iam_custom_policies = [neighbor for neighbor in graph.vs[iam_role.index].neighbors() if
                                                 neighbor['resource_type'] == AWS_IAM_ROLE_POLICY]
                connected_iam_aws_policies = [neighbor for neighbor in graph.vs[iam_role.index].neighbors() if
                                              neighbor['resource_type'] == AWS_IAM_ROLE_POLICY_ATTACHMENT]
                print(connected_iam_custom_policies)
                print(connected_iam_aws_policies)

                for policy in connected_iam_custom_policies:
                    policy_attributes = policy.attributes()
                    policy_name = policy_attributes['attr']['block_name_'].split('.')[1]
                    policy_content_json = policy_attributes['attr']['config_']['aws_iam_role_policy'][policy_name][
                        'policy']
                    has_admin_actions = get_admin_actions(
                        policy_content_json[0])  # todo aj check if more than 1 item can be present in the dict
                    if has_admin_actions:
                        return CheckResult.FAILED

                # todo aj for iam policy, we need to first describe the policy then check it's JSON. Do it later

        return result

    def get_evaluated_keys(self) -> List[str]:
        return ['user_data']


check = EC2WithAdminLikeAccess()
