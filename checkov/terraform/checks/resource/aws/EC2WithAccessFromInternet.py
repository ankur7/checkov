import re

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.secrets import string_has_secrets
from typing import List

AWS = 'aws'

AWS_INSTANCE = 'aws_instance'
AWS_LAUNCH_TEMPLATE = 'aws_launch_template'
AWS_LAUNCH_CONFIGURATION = 'aws_launch_configuration'
AWS_SECURITY_GROUP = 'aws_security_group'
# AWS_IAM_ROLE_POLICY = 'aws_iam_role_policy'
# AWS_IAM_ROLE_POLICY_ATTACHMENT = 'aws_iam_role_policy_attachment'  # AWS managed policies
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


class EC2Credentials(BaseResourceCheck):

    def __init__(self):
        name = "Block access from Internet except ports HTTP80/HTTPS443"
        id = "CKV_AWS_CUSTOM_02"
        supported_resources = [AWS_INSTANCE, AWS_LAUNCH_TEMPLATE, AWS_LAUNCH_CONFIGURATION]
        categories = [CheckCategories.SECRETS]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        vertices = graph.vs
        edges = graph.es

        aws_instance_list = vertices.select(resource_type=AWS_INSTANCE)
        # aws_instance_list = graph.vs.select(lambda vertex: vertex["resource_type"] == AWS_SECURITY_GROUP)
        for aws_instance in aws_instance_list:
            # all_neighbors_indices = graph.neighbors(aws_instance)
            # all_neighbors_vertices = [vertices[ind] for ind in all_neighbors_indices]
            # connected_iam_roles = [neighbor for neighbor in all_neighbors_vertices if neighbor['resource_type'] == AWS_IAM_ROLE]
            aws_instance_attributes = aws_instance.attributes()
            aws_instance_name = aws_instance_attributes['attr']['block_name_'].split('.')[1]

            connected_security_groups = [neighbor for neighbor in graph.vs[aws_instance.index].neighbors() if neighbor['resource_type'] == AWS_SECURITY_GROUP]

            for security_group in connected_security_groups:
                security_group_attributes = security_group.attributes()
                security_group_name = security_group_attributes['attr']['block_name_'].split('.')[1]
                ingress_list = security_group_attributes['attr']['config_']['aws_security_group'][security_group_name]['ingress']

                for ingress in ingress_list:
                    cidr_blocks = ingress.get('cidr_blocks', [None])[0]
                    from_port = ingress.get('from_port', [None])[0]
                    to_port = ingress.get('to_port', [None])[0]
                    protocol = ingress.get('protocol', ['TCP'])[0].upper() if 'protocol' in ingress else None


                    if '0.0.0.0/0' in cidr_blocks:
                        aws_instance_tags = aws_instance_attributes['attr']['config_']['aws_instance'][aws_instance_name]['tags']
                        if aws_instance_tags and isinstance(aws_instance_tags, list):
                            aws_instance_tags = aws_instance_tags[0]
                            tagged_exceptions = generate_tagged_exceptions(aws_instance_tags)

                            for port in range(int(from_port), int(to_port) + 1):
                                if f"{protocol}{from_port}" not in tagged_exceptions:
                                    return CheckResult.FAILED

        return result

    def get_evaluated_keys(self) -> List[str]:
        return ['user_data']


check = EC2Credentials()
