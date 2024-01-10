"""
Keep all the common functions in this class.
Those common functions that will be used in Kodiak IAC Scanning
"""

import re
import ipaddress
from typing import Union, Dict, List

from igraph import VertexSeq


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


def flatten(ingress_list):
    result = []
    for ingress in ingress_list:
        if isinstance(ingress, list):
            result.extend(flatten(ingress))
        else:
            result.append(ingress)
    return result


def flatten_cidr_blocks(cidr_blocks):
    result = []
    for block_list in cidr_blocks:
        if isinstance(block_list, list):
            for block in block_list:
                result.append(str(block))
        else:
            result.append(str(block_list))
    return result


def is_public_ip(input_value):
    """
    Checks if the input IP/CIDR is public IP or not.
    0.0.0.0/0 -> True
    103.43.112.97 -> True
    192.168.11.20 -> False
    :param input_value: IP or CIDR
    :return: True in case of Public IP. False in case of Private IP
    """
    if input_value == '0.0.0.0/0':
        return True
    try:
        network_obj = ipaddress.ip_network(input_value, strict=False)
        return not network_obj.is_private
    except ValueError:
        try:
            ip_obj = ipaddress.ip_address(input_value)
            return not ip_obj.is_private
        except ValueError:
            # Handle invalid IP address or CIDR
            return False  # Not a valid IP address


def get_sg_ingress_attributes(ingress: Dict[str, Union[int, str, list]]) -> Dict[str, Union[str, int]]:
    """
    Extract attributes from an Ingress dictionary (of a Security Group)

    Parameters:
    - ingress (Dict[str, Union[int, str, list]]): Input dictionary representing an ingress rule.

    Returns:
    - Dict[str, Union[str, int]]: Processed dictionary with keys: 'cidr_blocks', 'from_port', 'to_port', 'protocol'.
    """
    result = {
        'cidr_blocks': None,
        'from_port': None,
        'to_port': None,
        'protocol': 'TCP',  # Default value if 'protocol' is not specified
    }

    cidr_blocks = ingress.get('cidr_blocks')
    if cidr_blocks:
        result['cidr_blocks'] = flatten_cidr_blocks(cidr_blocks)

    from_port = ingress.get('from_port')
    if from_port:
        result['from_port'] = int(from_port[0]) if isinstance(from_port, list) else from_port

    to_port = ingress.get('to_port')
    if to_port:
        result['to_port'] = int(to_port[0]) if isinstance(to_port, list) else to_port

    protocol = ingress.get('protocol')
    if protocol:
        result['protocol'] = protocol[0].upper() if isinstance(protocol, list) and isinstance(protocol[0],
                                                                                              str) else protocol.upper()

    return result


def contains_exception_tag(resource_instance: VertexSeq, resource_type: str, tag_key: str, tag_value: Union[str, bool]) -> bool:
    """
    Checks if a resource has a specific tag with the expected value.

    Args:
        resource_instance: The resource to check.
        resource_type: The type of the resource.
        tag_key: The key of the tag to check.
        tag_value: The expected value of the tag.

    Returns:
        True if the resource has the tag with the expected value, False otherwise.
    """

    attributes = resource_instance.attributes()
    name = attributes['attr']['block_name_'].split('.')[1]  # Extract resource name
    tags = attributes['attr']['config_'][resource_type][name].get('tags')  # Access tags directly

    if not tags:
        return False

    if isinstance(tags, list):
        tags = tags[0]

    return tag_key in tags and tags[tag_key] == tag_value


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


def is_tagged_for_exceptions(resource_instance: VertexSeq, resource_type: str, from_port: int, to_port: int,
                             protocol: str) -> Union[bool, None]:
    """
    Check if the AWS Instance has the correct tags for the exception.

    :param resource_instance: VertexSeq for the AWS Instance/Launch Configuration/Launch Template.
    :param resource_type: Type of resource eg: AWS_INSTANCE, LAUNCH_CONFIG, AWS_ELB
    :param from_port: From port of the ingress rule.
    :param to_port: To port of the ingress rule.
    :param protocol: Protocol of the ingress rule.
    :return: True if the instance is tagged correctly for the exception, False otherwise.
    """
    resource_instance_attributes = resource_instance.attributes()
    resource_instance_name: str = resource_instance_attributes['attr']['block_name_'].split('.')[1]

    resource_instance_tags: Union[List, Dict] = resource_instance_attributes['attr']['config_'][resource_type][resource_instance_name].get('tags')

    if resource_instance_tags and isinstance(resource_instance_tags, list):
        resource_instance_tags = resource_instance_tags[0]
        tagged_exceptions = generate_tagged_exceptions(resource_instance_tags)

        for port in range(from_port, to_port + 1):
            if f"{protocol}{port}" in tagged_exceptions:
                return True

