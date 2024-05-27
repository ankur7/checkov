"""
Keep all the common functions in this class.
Those common functions that will be used in Kodiak IAC Scanning
"""

import re
import ipaddress
from typing import Union, Dict, List, Any

import rustworkx as rx


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


class CustomVertex:
    def __init__(self, node_index: int, node_data: Dict[str, Any]):
        self.node_index = node_index
        self.node_data = node_data


def flatten(ingress_list):
    """
    Flatten the ingress list
    :param ingress_list:  Ingress list
    :return:  Flattened ingress list
    """
    result = []
    for ingress in ingress_list:
        if isinstance(ingress, list):
            result.extend(flatten(ingress))
        else:
            result.append(ingress)
    return result


def flatten_cidr_blocks(cidr_blocks) -> List[str]:
    """
    Flatten the CIDR blocks list
    :param cidr_blocks: CIDR blocks list
    :return: Flattened CIDR blocks list
    """
    result = []
    for block_list in cidr_blocks:
        if isinstance(block_list, list):
            for block in block_list:
                result.append(str(block))
        else:
            result.append(str(block_list))
    return result


def is_public_ip(input_value) -> bool:
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


def contains_exception_tag(resource_instance: dict, resource_type: str, tag_key: str, tag_values: List[Union[str, bool]]) -> bool:
    """
    Checks if a resource has a specific tag with the expected value.

    Args:
        resource_instance: The resource to check.
        resource_type: The type of the resource.
        tag_key: The key of the tag to check.
        tag_values: One of the expected value of the tag. Handles both string and boolean values. eg. [True, 'True']

    Returns:
        True if the resource has the tag with the expected value, False otherwise.
    """

    name = resource_instance['block_name_'].split('.')[1]  # Extract resource name
    tags = resource_instance['config_'][resource_type][name].get('tags')  # Access tags directly

    if not tags:
        return False

    if isinstance(tags, list):
        tags = tags[0]

    return tag_key in tags and tags[tag_key] in tag_values


def generate_tagged_exceptions(tags: dict) -> dict:
    """
    Generates a dictionary of exceptions from the tags of a resource.
    :param tags: The tags of the resource.
    :return: A dictionary of exceptions.
    """
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


def is_tagged_for_exceptions(resource_instance: CustomVertex, resource_type: str, from_port: int, to_port: int,
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
    resource_instance_attributes: dict = resource_instance.node_data
    resource_instance_name: str = resource_instance_attributes['block_name_'].split('.')[1]

    resource_instance_tags: Union[List, Dict] = resource_instance_attributes['config_'][resource_type][resource_instance_name].get('tags')

    if resource_instance_tags and isinstance(resource_instance_tags, list):
        resource_instance_tags = resource_instance_tags[0]
        tagged_exceptions = generate_tagged_exceptions(resource_instance_tags)

        for port in range(from_port, to_port + 1):
            if f"{protocol}{port}" in tagged_exceptions:
                return True


def connected_to_auto_scaling_group(graph: rx.PyDiGraph, launch_temp_or_launch_conf: CustomVertex, resource_type: str) -> bool:
    """
    Check if the launch template or launch configuration is connected to an auto scaling group
    :param graph: graph instance
    :param launch_temp_or_launch_conf: launch template or launch configuration vertex
    :return: True if the launch template or launch configuration is connected to an auto scaling group, False otherwise
    """
    # todo aj handle this for PyDiGraph
    # connected_auto_scaling_groups = [neighbor for neighbor in graph.vs[launch_temp_or_launch_conf.index].neighbors() if
    #                                  neighbor['resource_type'] == 'aws_autoscaling_group']

    connected_auto_scaling_groups: List[CustomVertex] = find_neighbors_with_resource_type(graph, launch_temp_or_launch_conf, 'aws_autoscaling_group')

    if connected_auto_scaling_groups:
        return True
    return False


def find_neighbors_with_resource_type(graph: rx.PyDiGraph, vertex: CustomVertex, resource_type: str) -> List[CustomVertex]:
    """
    Find neighbors of a vertex with a specific resource type
    :param graph: PyDiGraph instance
    :param vertex: PyDiGraph vertex
    :param resource_type: resource type to filter by (eg: 'aws_instance', 'aws_launch_configuration')
    :return:
    """
    # Access the adjacency list for the given vertex
    neighbors = graph.adj(vertex.node_index)
    matching_neighbors = []

    for neighbor_index in neighbors:
        node_index, node_data = graph.get_node_data(neighbor_index)
        if node_data.get('resource_type') == resource_type:
            matching_neighbors.append(CustomVertex(node_index, node_data))

    return matching_neighbors


def filter_nodes_by_resource_type(graph: rx.PyDiGraph, address: str, resource_types: list[str]) -> list[CustomVertex]:
    """
    Filter nodes by address and resource type
    :param graph: PyDiGraph instance
    :param address: address to filter by
    :param resource_types: list of resource types to filter by
    :return:
    """
    filtered_nodes = []
    for node in graph.nodes():
        # Assuming node_data is a tuple (identifier, data_dict)
        node_index, data_dict = node
        if data_dict.get('__address__') == address and data_dict.get("resource_type") in resource_types:
            filtered_nodes.append(CustomVertex(node_index, data_dict))
    return filtered_nodes
