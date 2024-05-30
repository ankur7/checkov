
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import contains_exception_tag, filter_nodes_by_resource_type, \
    CustomVertex

AWS_S3_BUCKET = "aws_s3_bucket"
PAB_REQUIREMENTS = {
    'block_public_acls': True,
    'ignore_public_acls': True,
    'block_public_policy': True,
    'restrict_public_buckets': True
}


class S3BlockPublicRead(BaseResourceCheck):

    def __init__(self):
        name = "Block public access to S3 buckets"
        id = "CKV_AWS_STORAGE_0008"
        supported_resources = ['aws_s3_bucket']
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        result = CheckResult.PASSED
        all_graphs = conf.get('runner_filter_all_graphs', None)
        if all_graphs:
            graph = all_graphs[0][0]
        else:
            return result

        # aws_s3_bucket_list = graph.vs.select(
        #     lambda vertex: vertex['attr'].get('__address__') == str(conf["__address__"]) and (
        #             vertex["resource_type"] == AWS_S3_BUCKET
        #     )
        # )

        aws_s3_bucket_list: list[CustomVertex] = filter_nodes_by_resource_type(graph, str(conf["__address__"]), [AWS_S3_BUCKET])

        for custom_vertex in aws_s3_bucket_list:
            s3_bucket_attributes = custom_vertex.node_data
            # s3_bucket_attributes = aws_s3_bucket.attributes()
            for pab_setting in PAB_REQUIREMENTS:
                if not s3_bucket_attributes.get(pab_setting, None):
                    if contains_exception_tag(s3_bucket_attributes, AWS_S3_BUCKET, tag_key="Adobe:DataClassification",
                                              tag_values=["Public"]):
                        continue
                    else:
                        return CheckResult.FAILED
        return result


check = S3BlockPublicRead()