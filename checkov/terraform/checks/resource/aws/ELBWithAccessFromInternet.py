import re
from typing import List

from igraph import Vertex

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import flatten, get_sg_ingress_attributes, \
    is_tagged_for_exceptions

AWS_ELB = 'aws_elb'  # Classic Load Balancer
AWS_LB = 'aws_lb'    # Application Load Balancer
# AWS_LB = 'aws_lb'    # Network Load Balancer
AWS_SECURITY_GROUP = 'aws_security_group'


def _is_elb_publicly_accessible(graph, resource_instance: Vertex, resource_instance_type: str) -> bool:

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
            from_port = ingress_attributes.get('from_port', None)
            to_port = ingress_attributes.get('to_port', None)
            protocol = ingress_attributes.get('protocol', None)

            if not cidr_blocks:
                continue

            if '0.0.0.0/0' in cidr_blocks:
                for port in range(int(from_port), int(to_port) + 1):
                    if is_tagged_for_exceptions(resource_instance, resource_instance_type, from_port, to_port, protocol):
                        continue
                    else:
                        return True


class ELBWithAccessFromInternet(BaseResourceCheck):
    """
    In case of a classic load balancer, the security group is not attached with the lb. Instead, the security group is
    attached with the ec2 instances. So, we need to check the security group of the ec2 instances attached with the lb.
    In case of an application load balancer and network load balancer, the security group is attached with the lb
    """
    def __init__(self):
        name = "Block inbound access from the Internet (Source IP: 0.0.0.0/0) on ports other than 80 and 443 for ELBs"
        id = "CKV_AWS_NETWORK_0004"
        supported_resources = [AWS_LB, AWS_ELB]
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf) -> CheckResult:
        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        aws_elb_list = graph.vs.select(lambda vertex: vertex['attr'].get('__address__') == conf["__address__"] and (
                                                      vertex["resource_type"] == AWS_ELB
                                       ))

        aws_lb_list = graph.vs.select(lambda vertex: vertex['attr'].get('__address__') == conf["__address__"] and (
                                                      vertex["resource_type"] == AWS_LB
                                       ))

        for aws_elb in aws_elb_list:
            is_publicly_accessible = _is_elb_publicly_accessible(graph, aws_elb, AWS_ELB)
            if is_publicly_accessible:
                return CheckResult.FAILED

        for aws_lb in aws_lb_list:
            is_publicly_accessible = _is_elb_publicly_accessible(graph, aws_lb, AWS_LB)
            if is_publicly_accessible:
                return CheckResult.FAILED

        return result


check = ELBWithAccessFromInternet()
