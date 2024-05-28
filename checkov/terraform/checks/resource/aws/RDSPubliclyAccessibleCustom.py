import rustworkx as rx

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import flatten, is_public_ip, get_sg_ingress_attributes, \
    filter_nodes_by_resource_type, CustomVertex, find_neighbors_with_resource_type

AWS_DB_INSTANCE = 'aws_db_instance'
AWS_RDS_CLUSTER_INSTANCE = 'aws_rds_cluster_instance'
AWS_SECURITY_GROUP = 'aws_security_group'


def _is_rds_publicly_accessible(graph: rx.PyDiGraph, aws_rds: CustomVertex):
    """
    Check if the RDS is publicly accessible
    :param graph: graph instance
    :param aws_rds: aws_rds vertex
    :return: True if the RDS is publicly accessible, False otherwise
    """
    # aws_rds_attributes = aws_rds.attributes()
    aws_rds_attributes = aws_rds.node_data

    if aws_rds_attributes.get('publicly_accessible'):
        return True

    # connected_security_groups = [neighbor for neighbor in graph.vs[aws_rds.index].neighbors() if
    #                              neighbor['resource_type'] == AWS_SECURITY_GROUP]

    connected_security_groups: list[CustomVertex] = find_neighbors_with_resource_type(graph, aws_rds, AWS_SECURITY_GROUP)

    for custom_vertex in connected_security_groups:
        # security_group_attributes = security_group.attributes()

        security_group_attributes = custom_vertex.node_data
        security_group_name = security_group_attributes['block_name_'].split('.')[1]
        ingress_list = security_group_attributes['config_'][AWS_SECURITY_GROUP][security_group_name].get('ingress')

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


class RDSPubliclyAccessibleCustom(BaseResourceCheck):
    def __init__(self):
        name = "Block external access to RDS databases"
        id = "CKV_AWS_SERVICE_0010"
        supported_resources = ['aws_db_instance', 'aws_rds_cluster_instance']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        # aws_rds_list = graph.vs.select(lambda vertex: vertex['attr'].get('__address__') == str(conf["__address__"]) and (
        #         vertex["resource_type"] == AWS_DB_INSTANCE or
        #         vertex["resource_type"] == AWS_RDS_CLUSTER_INSTANCE
        # ))

        aws_rds_list: list[CustomVertex] = filter_nodes_by_resource_type(graph, str(conf["__address__"]),
                                                                         [AWS_DB_INSTANCE, AWS_RDS_CLUSTER_INSTANCE])

        for custom_vertex in aws_rds_list:
            is_publicly_accessible = _is_rds_publicly_accessible(graph, custom_vertex)

            if is_publicly_accessible:
                return CheckResult.FAILED

        return result


check = RDSPubliclyAccessibleCustom()
