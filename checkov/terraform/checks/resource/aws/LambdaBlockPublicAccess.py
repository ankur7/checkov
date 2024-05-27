from typing import Dict, List, Any

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import filter_nodes_by_resource_type, CustomVertex, \
    find_neighbors_with_resource_type

AWS_LAMBDA_FUNCTION = 'aws_lambda_function'
AWS_LAMBDA_PERMISSION = 'aws_lambda_permission'


class LambdaBlockPublicAccess(BaseResourceCheck):
    """
        Looks for block public access configuration at aws_lambda_function
        https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html
    """
    def __init__(self) -> None:
        name = "Block public access to Lambda functions"
        id = "CKV_AWS_SERVICE_0001"
        supported_resources = [AWS_LAMBDA_FUNCTION]
        categories = [CheckCategories.SECRETS]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: Dict[str, List[Any]]) -> CheckResult:
        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        # aws_lambda_function_list = graph.vs.select(lambda vertex: vertex['attr'].get('__address__') == str(conf["__address__"]) and (
        #                                                           vertex["resource_type"] == AWS_LAMBDA_FUNCTION)
        #                                            )

        aws_lambda_function_list = filter_nodes_by_resource_type(graph, str(conf["__address__"]), [AWS_LAMBDA_FUNCTION])

        for custom_vertex in aws_lambda_function_list:

            aws_lambda_permission_list = find_neighbors_with_resource_type(graph, custom_vertex, AWS_LAMBDA_PERMISSION)

            # aws_lambda_permission_list = [neighbor for neighbor in graph.vs[aws_lambda_function.index].neighbors() if
            #                               neighbor['resource_type'] == AWS_LAMBDA_PERMISSION]

            for custom_vertex1 in aws_lambda_permission_list:
                aws_lambda_permission = custom_vertex1.node_data
                if aws_lambda_permission.get('principal') == "*":
                    return CheckResult.FAILED

        return result


check = LambdaBlockPublicAccess()
