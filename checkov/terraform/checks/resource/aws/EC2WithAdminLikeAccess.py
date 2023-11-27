import re
import ipaddress
from typing import List

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.secrets import string_has_secrets

AWS = 'aws'

AWS_INSTANCE = 'aws_instance'
AWS_LAUNCH_TEMPLATE = 'aws_launch_template'
AWS_LAUNCH_CONFIGURATION = 'aws_launch_configuration'
AWS_IAM_ROLE = 'aws_iam_role'
AWS_IAM_ROLE_POLICY = 'aws_iam_role_policy'
AWS_IAM_ROLE_POLICY_ATTACHMENT = 'aws_iam_role_policy_attachment'  # AWS managed policies
AWS_SECURITY_GROUP = 'aws_security_group'

PUBLIC_PORT_TAG_KEYS = [
    "Adobe:PublicPorts",
    "Adobe.PublicPorts",
    "Adobe-PublicPorts"
]

JUSTIFICATION_TAG_KEYS = [
    "Adobe:PortJustification",
    "Adobe.PortJustification",
    "Adobe-PortJustification"
]


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


def generate_tagged_exceptions(tags: dict):
    # print("Generating tagged exceptions")

    publicPortString = ""
    publicPortJustification = "None Specified"
    exceptions = {}
    exceptionTagKey = ""

    for k in PUBLIC_PORT_TAG_KEYS:
        if k in tags:
            publicPortString = str(tags[k])
            exceptionTagKey = k
            break

    for k in JUSTIFICATION_TAG_KEYS:
        if k in tags:
            publicPortJustification = str(tags[k])
            break

    publicPortsStringList = publicPortString.split(",")
    for portstring in publicPortsStringList:
        port = None
        proto = None
        range_list = []
        if portstring:
            # re.search returns Nonetype upon a non-match
            # changing code structure to using if-else statements, no longer need exception catching
            portstring = portstring.strip()
            if re.search("^(TCP|UDP)?\ *(\d+\ *-\ *\d+|\d+)$", portstring):  # noqa: W605
                proto = re.search("TCP|UDP", portstring)
                if proto:
                    proto = proto.group(0)
                else:
                    proto = "TCP"

                port_range = re.search("\d+\ *\-\ *\d+$", portstring)  # noqa: W605
                if port_range:
                    port_range = port_range.group(0)
                    port_range = port_range.split("-")
                    port_range = [p.strip() for p in port_range]
                    if int(port_range[0]) > int(port_range[1]):
                        print(f"Invalid port range {port_range[0]} to {port_range[1]}")
                    else:
                        range_list = [str(i) for i in range(int(port_range[0]), int(port_range[1]) + 1)]
                else:
                    print(f"Missing port range in {portstring}")
                    print("Finding single port")
                    portstring = portstring.strip()

                    port = re.search("\d+$", portstring)  # noqa: W605
                    if port:
                        port = port.group(0)
                    else:
                        print(f"Missing port number in {portstring}")
            else:
                print(f"Malformed input {portstring}")
                continue

        if port:
            proto_port = "%s%s" % (proto, port)
            exceptions[proto_port] = {
                "justification": publicPortJustification,
                "exceptionSource": exceptionTagKey,
                "port": port
            }
        elif range_list:
            for port in range_list:
                proto_port = "%s%s" % (proto, port)
                exceptions[proto_port] = {
                    "justification": publicPortJustification,
                    "exceptionSource": exceptionTagKey,
                    "port": port
                }
    return exceptions


def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private
    except ValueError:
        return False  # Not a valid IP address


def is_ec2_instance_publicly_accessible(graph, aws_instance):
    aws_instance_attributes = aws_instance.attributes()
    aws_instance_name = aws_instance_attributes['attr']['block_name_'].split('.')[1]

    connected_security_groups = [neighbor for neighbor in graph.vs[aws_instance.index].neighbors() if
                                 neighbor['resource_type'] == AWS_SECURITY_GROUP]

    for security_group in connected_security_groups:
        security_group_attributes = security_group.attributes()
        security_group_name = security_group_attributes['attr']['block_name_'].split('.')[1]
        ingress_list = security_group_attributes['attr']['config_']['aws_security_group'][security_group_name].get('ingress')

        if not ingress_list:
            continue  # no ingress_list, cannot check

        for ingress in ingress_list:
            # cidr_blocks = ingress.get('cidr_blocks', [None])[0]
            cidr_blocks = ingress.get('cidr_blocks')
            if cidr_blocks:
                cidr_blocks = cidr_blocks[0]
            else:
                continue  # no cidr blocks, cannot check

            from_port = ingress.get('from_port', [None])[0]
            to_port = ingress.get('to_port', [None])[0]
            protocol = ingress.get('protocol', ['TCP'])[0].upper() if 'protocol' in ingress else None


            for ip_or_cidr in cidr_blocks:
                if is_public_ip(ip_or_cidr):
                    return True
            # if '0.0.0.0/0' in cidr_blocks:
            #     aws_instance_tags = aws_instance_attributes['attr']['config_']['aws_instance'][aws_instance_name]['tags']
            #     if aws_instance_tags and isinstance(aws_instance_tags, list):
            #         aws_instance_tags = aws_instance_tags[0]
            #         tagged_exceptions = generate_tagged_exceptions(aws_instance_tags)
            #
            #         for port in range(int(from_port), int(to_port) + 1):
            #             if f"{protocol}{from_port}" not in tagged_exceptions:
            #                 return True



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

        # aws_instance_list = vertices.select(resource_type=AWS_INSTANCE)
        aws_instance_list = graph.vs.select(lambda vertex: vertex["resource_type"] == AWS_INSTANCE or
                                                           vertex["resource_type"] == AWS_LAUNCH_TEMPLATE or
                                                           vertex["resource_type"] == AWS_LAUNCH_CONFIGURATION
                                            )
        for aws_instance in aws_instance_list:

            # First check if aws_instance is publicly accessible
            is_publicly_accessible = is_ec2_instance_publicly_accessible(graph, aws_instance)

            if not is_publicly_accessible:
                continue

            # EC2 instance is publicly accessible, now check admin like policies

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
