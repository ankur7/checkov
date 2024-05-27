
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import contains_exception_tag, filter_nodes_by_resource_type, CustomVertex

AWS_AMI = 'aws_ami'
AWS_AMI_LAUNCH_PERMISSION = 'aws_ami_launch_permission'


class AMIBlockPublicAccess(BaseResourceCheck):
    """
    Looks for public access to AMIs.
    For now ignoring the case where the AMI is shared with other AWS accounts, because we don't have the Adobe account IDs.
    Or we cannot make any calls to get Adobe account IDs during Kodiak scan.
    """
    def __init__(self):
        """
        Two ways to make an AMI public:
        1. Setting public = True in aws_ami resource
        2. Adding a launch_permission with 'all' as the group
        https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ami_launch_permission
        """
        name = "Ensure AMIs are never shared with the public"
        id = "CKV_AWS_COMPUTE_0002"
        supported_resources = [AWS_AMI, AWS_AMI_LAUNCH_PERMISSION]
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf) -> CheckResult:

        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        # resource_list: List[Vertex] = graph.vs.select(
        #     lambda vertex: vertex['attr'].get('__address__') == conf["__address__"] and (
        #             vertex["resource_type"] == AWS_AMI or
        #             vertex["resource_type"] == AWS_AMI_LAUNCH_PERMISSION
        #     ))
        #

        resource_list: list[CustomVertex] = filter_nodes_by_resource_type(graph, conf["__address__"], [AWS_AMI, AWS_AMI_LAUNCH_PERMISSION])

        for custom_vertex in resource_list:
            node_index, resource_instance = custom_vertex.node_index, custom_vertex.node_data
            if resource_instance['resource_type'] == AWS_AMI:
                public = resource_instance.get('public', None)
                if public:
                    if contains_exception_tag(resource_instance, AWS_AMI, tag_key="Adobe:DataClassification",
                                              tag_values=["Public"]):
                        continue
                    else:
                        return CheckResult.FAILED
            elif resource_instance['resource_type'] == AWS_AMI_LAUNCH_PERMISSION:
                group = resource_instance.get('group', None)
                if group and group == 'all':
                    if contains_exception_tag(resource_instance, AWS_AMI_LAUNCH_PERMISSION, tag_key="Adobe:DataClassification",
                                              tag_values=["Public"]):
                        continue
                    else:
                        return CheckResult.FAILED

        return result

check = AMIBlockPublicAccess()

    # def scan_resource_conf(self, conf) -> CheckResult:
    #
    #     if conf.get('launch_permission'):
    #
    #         # 'user_ids' is mandatory inside a launch_permission
    #         user_ids = conf['launch_permission'][0].get('user_ids', None)
    #
    #         if user_ids:
    #             user_ids = user_ids[0]
    #         for user_id in user_ids:
    #             if user_id.lower() == 'all':
    #                 return CheckResult.FAILED
    #
    #     if conf.get('account_id'):  # through aws_ami_launch_permission todo aj handle this better
    #         if conf['account_id'][0].lower() == 'all':
    #             return CheckResult.FAILED
    #
    #     return CheckResult.PASSED


