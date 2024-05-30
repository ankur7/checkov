from typing import Dict, List

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import filter_nodes_by_resource_type, CustomVertex, \
    find_neighbors_with_resource_type

#
AWS_SQS_QUEUE = 'aws_sqs_queue'
AWS_SQS_QUEUE_POLICY = 'aws_sqs_queue_policy'


def does_policy_allow_public_access(policy: Dict) -> bool:
    """
    Checks if the policy allows public access
    :param policy: the policy to check
    :return: True if the policy allows public access, False otherwise
    """
    if isinstance(policy, dict):
        if policy.get('Statement'):
            for statement in policy['Statement']:
                if statement.get('Principal') == '*':
                    return True
    return False


class SQSBlockPublicAccess(BaseResourceCheck):
    """
    Looks for block public access configuration at aws_sqs_queue
    https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-setting-up.html
    """

    def __init__(self):
        name = "Block public access to SQS queues"
        id = "CKV_AWS_SERVICE_0005"
        supported_resources = [AWS_SQS_QUEUE]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        aws_sqs_queue_list: list[CustomVertex] = filter_nodes_by_resource_type(graph, str(conf["__address__"]), [AWS_SQS_QUEUE])

        # aws_sqs_queue_list: List[Vertex] = graph.vs.select(
        #     lambda vertex: vertex['attr'].get('__address__') == str(conf["__address__"])
        #                    and (vertex["resource_type"] == AWS_SQS_QUEUE)
        #     )

        for custom_vertex in aws_sqs_queue_list:
            # aws_sqs_queue_policy_list = [neighbor for neighbor in graph.vs[aws_sqs_queue.index].neighbors() if
            #                              neighbor['resource_type'] == AWS_SQS_QUEUE_POLICY]

            aws_sqs_queue_policy_list: list[CustomVertex] = find_neighbors_with_resource_type(graph, custom_vertex, AWS_SQS_QUEUE_POLICY)
            for custom_vertex1 in aws_sqs_queue_policy_list:
                aws_sqs_queue_policy = custom_vertex1.node_data
                policy = aws_sqs_queue_policy.get('policy', [{}])
                if does_policy_allow_public_access(policy):
                    return CheckResult.FAILED

        return result

        #
        # if "policy" in conf.keys():
        #     policy = conf["policy"][0]
        #     if type(policy) is dict:
        #         statement = policy['Statement'][0]
        #         if type(statement) is dict:
        #             if statement['Principal'] == '*':
        #                 return CheckResult.FAILED
        # return CheckResult.PASSED

    def get_evaluated_keys(self) -> List[str]:
        return ['policy']


check = SQSBlockPublicAccess()