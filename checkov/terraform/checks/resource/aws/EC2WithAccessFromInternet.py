from typing import List

import rustworkx as rx

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import flatten, get_sg_ingress_attributes,\
    is_tagged_for_exceptions, connected_to_auto_scaling_group, filter_nodes_by_resource_type, CustomVertex, \
    find_neighbors_with_resource_type


AWS = 'aws'

AWS_INSTANCE = 'aws_instance'
AWS_LAUNCH_TEMPLATE = 'aws_launch_template'
AWS_LAUNCH_CONFIGURATION = 'aws_launch_configuration'
AWS_SECURITY_GROUP = 'aws_security_group'
AWS_AUTOSCALING_GROUP = 'aws_autoscaling_group'


def _is_ec2_instance_publicly_accessible(graph: rx.PyDiGraph, resource_instance: CustomVertex, resource_instance_type: str):
    """
    Check if the EC2 instance is publicly accessible
    :param graph:  graph instance
    :param resource_instance: resource vertex
    :param resource_instance_type: aws_instance or aws_launch_template or aws_launch_configuration
    :return: True if the EC2 instance is publicly accessible, False otherwise
    """

    neighbours = graph.adj(resource_instance.node_index)

    connected_security_groups: List[CustomVertex] = find_neighbors_with_resource_type(graph, resource_instance, AWS_SECURITY_GROUP)

    # connected_security_groups = [neighbor for neighbor in graph.vs[resource_instance.index].neighbors() if
    #                              neighbor['resource_type'] == AWS_SECURITY_GROUP]

    for custom_vertex in connected_security_groups:
        security_group_attributes = custom_vertex.node_data

        # security_group_attributes = security_group.attributes()
        security_group_name = security_group_attributes['block_name_'].split('.')[1]

        ingress_list = security_group_attributes['config_'][AWS_SECURITY_GROUP][security_group_name].get('ingress')

        if not ingress_list:
            continue  # no ingress_list, cannot check

        ingress_list = flatten(ingress_list)

        for ingress in ingress_list:
            ingress_attributes = get_sg_ingress_attributes(ingress)

            cidr_blocks = ingress_attributes.get('cidr_blocks', None)
            from_port = ingress_attributes.get('from_port', None)
            to_port = ingress_attributes.get('to_port', None)
            protocol = ingress_attributes.get('protocol', None)

            if '0.0.0.0/0' in cidr_blocks:
                for port in range(int(from_port), int(to_port) + 1):
                    if is_tagged_for_exceptions(resource_instance, resource_instance_type, from_port, to_port, protocol):
                        continue
                    else:
                        return True


class EC2WithAccessFromInternet(BaseResourceCheck):

    def __init__(self):
        name = "Block access from Internet (Source IP: 0.0.0.0/0) except ports HTTP80/HTTPS443"
        id = "CKV_AWS_NETWORK_0002"
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

        # aws_instance_list = graph.vs.select(
        #     lambda vertex: vertex['attr'].get('__address__') == str(conf["__address__"]) and (
        #             vertex["resource_type"] == AWS_INSTANCE
        #     )
        #     )

        aws_instance_list: list[CustomVertex] = filter_nodes_by_resource_type(graph, str(conf["__address__"]), [AWS_INSTANCE])

        for custom_vertex in aws_instance_list:
            is_publicly_accessible = _is_ec2_instance_publicly_accessible(graph, custom_vertex, AWS_INSTANCE)
            if is_publicly_accessible:
                return CheckResult.FAILED

        # launch_template_list = graph.vs.select(
        #     lambda vertex: vertex['attr'].get('__address__') == str(conf["__address__"]) and (
        #             vertex["resource_type"] == AWS_LAUNCH_TEMPLATE
        #     )
        #     )

        launch_template_list = filter_nodes_by_resource_type(graph, str(conf["__address__"]), [AWS_LAUNCH_TEMPLATE])

        for launch_template in launch_template_list:
            if not connected_to_auto_scaling_group(graph, launch_template, AWS_LAUNCH_TEMPLATE):
                continue

            is_publicly_accessible = _is_ec2_instance_publicly_accessible(graph, launch_template, AWS_LAUNCH_TEMPLATE)
            if is_publicly_accessible:
                return CheckResult.FAILED

        launch_configuration_list = graph.vs.select(
            lambda vertex: vertex['attr'].get('__address__') == str(conf["__address__"]) and (
                    vertex["resource_type"] == AWS_LAUNCH_CONFIGURATION
            )
            )

        for launch_configuration in launch_configuration_list:
            if not connected_to_auto_scaling_group(graph, launch_configuration, AWS_LAUNCH_CONFIGURATION):
                continue

            is_publicly_accessible = _is_ec2_instance_publicly_accessible(graph, launch_configuration,
                                                                          AWS_LAUNCH_CONFIGURATION)
            if is_publicly_accessible:
                return CheckResult.FAILED

        return result

    def get_evaluated_keys(self) -> List[str]:
        return ['user_data']


check = EC2WithAccessFromInternet()
