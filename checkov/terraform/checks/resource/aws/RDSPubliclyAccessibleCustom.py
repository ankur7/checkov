import ipaddress

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

AWS_DB_INSTANCE = 'aws_db_instance'
AWS_RDS_CLUSTER_INSTANCE = 'aws_rds_cluster_instance'
AWS_SECURITY_GROUP = 'aws_security_group'


def is_public_ip(input_value):
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
            return False # Not a valid IP address

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


def is_rds_publicly_accessible(graph, aws_rds):
    aws_rds_attributes = aws_rds.attributes()

    if aws_rds_attributes['attr'].get('publicly_accessible'):
        return True

    aws_rds_name = aws_rds_attributes['attr']['block_name_'].split('.')[1]

    connected_security_groups = [neighbor for neighbor in graph.vs[aws_rds.index].neighbors() if
                                 neighbor['resource_type'] == AWS_SECURITY_GROUP]

    for security_group in connected_security_groups:
        security_group_attributes = security_group.attributes()
        security_group_name = security_group_attributes['attr']['block_name_'].split('.')[1]
        ingress_list = security_group_attributes['attr']['config_']['aws_security_group'][security_group_name].get('ingress')

        if not ingress_list:
            continue  # no ingress_list, cannot check

        ingress_list = flatten(ingress_list)

        for ingress in ingress_list:
            # cidr_blocks = ingress.get('cidr_blocks', [None])[0]
            cidr_blocks = ingress.get('cidr_blocks')
            if cidr_blocks:
                cidr_blocks = flatten_cidr_blocks(cidr_blocks)
            else:
                continue  # no cidr blocks, cannot check

            from_port = ingress.get('from_port')
            if from_port:
                if isinstance(from_port, list):
                    from_port = from_port[0]

            to_port = ingress.get('to_port')
            if to_port:
                if isinstance(to_port, list):
                    to_port = to_port[0]

            protocol = ingress.get('protocol', 'TCP')
            if protocol:
                if isinstance(protocol, list):
                    protocol = protocol[0]
                    if isinstance(protocol, str):
                        protocol = protocol.upper()

            # from_port = ingress.get('from_port', [None])[0]
            # to_port = ingress.get('to_port', [None])[0]
            # protocol = ingress.get('protocol', ['TCP'])[0].upper() if 'protocol' in ingress else None

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

        aws_rds_list = graph.vs.select(lambda vertex: vertex["resource_type"] == AWS_DB_INSTANCE or
                                                      vertex["resource_type"] == AWS_RDS_CLUSTER_INSTANCE
                                       )

        for aws_rds in aws_rds_list:
            is_publicly_accessible = is_rds_publicly_accessible(graph, aws_rds)

            if is_publicly_accessible:
                return CheckResult.FAILED

        return result

check = RDSPubliclyAccessibleCustom()
