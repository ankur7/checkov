from typing import List

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import flatten, get_sg_ingress_attributes, is_tagged_for_exceptions, contains_exception_tag


AWS = 'aws'

AWS_INSTANCE = 'aws_instance'
AWS_LAUNCH_TEMPLATE = 'aws_launch_template'
AWS_LAUNCH_CONFIGURATION = 'aws_launch_configuration'
AWS_SECURITY_GROUP = 'aws_security_group'
AWS_AUTOSCALING_GROUP = 'aws_autoscaling_group'


def _is_ec2_instance_publicly_accessible(graph, resource_instance, resource_instance_type):
    connected_security_groups = [neighbor for neighbor in graph.vs[resource_instance.index].neighbors() if
                                 neighbor['resource_type'] == AWS_SECURITY_GROUP]

    for security_group in connected_security_groups:
        security_group_attributes = security_group.attributes()
        security_group_name = security_group_attributes['attr']['block_name_'].split('.')[1]

        ingress_list = security_group_attributes['attr']['config_']['aws_security_group'][security_group_name].get(
            'ingress')

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


def connected_to_auto_scaling_group(graph, launch_temp_or_launch_conf):
    connected_auto_scaling_groups = [neighbor for neighbor in graph.vs[launch_temp_or_launch_conf.index].neighbors() if
                                     neighbor['resource_type'] == AWS_AUTOSCALING_GROUP]
    if connected_auto_scaling_groups:
        return True
    return False


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

        aws_instance_list = graph.vs.select(
            lambda vertex: vertex['attr'].get('__address__') == conf["__address__"] and (
                    vertex["resource_type"] == AWS_INSTANCE
            )
            )

        for aws_instance in aws_instance_list:
            is_publicly_accessible = _is_ec2_instance_publicly_accessible(graph, aws_instance, AWS_INSTANCE)
            if is_publicly_accessible:
                return CheckResult.FAILED

        launch_template_list = graph.vs.select(
            lambda vertex: vertex['attr'].get('__address__') == conf["__address__"] and (
                    vertex["resource_type"] == AWS_LAUNCH_TEMPLATE
            )
            )

        for launch_template in launch_template_list:
            if not connected_to_auto_scaling_group(graph, launch_template):
                continue

            is_publicly_accessible = _is_ec2_instance_publicly_accessible(graph, launch_template, AWS_LAUNCH_TEMPLATE)
            if is_publicly_accessible:
                return CheckResult.FAILED

        launch_configuration_list = graph.vs.select(
            lambda vertex: vertex['attr'].get('__address__') == conf["__address__"] and (
                    vertex["resource_type"] == AWS_LAUNCH_CONFIGURATION
            )
            )

        for launch_configuration in launch_configuration_list:
            if not connected_to_auto_scaling_group(graph, launch_configuration):
                continue

            is_publicly_accessible = _is_ec2_instance_publicly_accessible(graph, launch_configuration,
                                                                          AWS_LAUNCH_CONFIGURATION)
            if is_publicly_accessible:
                return CheckResult.FAILED

        return result

    def get_evaluated_keys(self) -> List[str]:
        return ['user_data']


check = EC2WithAccessFromInternet()
