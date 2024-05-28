
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.terraform.checks.resource.aws.iac_common import filter_nodes_by_resource_type, CustomVertex

AWS_S3_BUCKET = "aws_s3_bucket"


class S3BlockPublicWrite(BaseResourceCheck):
    """
    Checking if the bucket acl to determine if write access is enabled on an S3 bucket or not
    This is only half implemented. Bucket objects may have different ACLs than the bucket.
    Most probably no-one will be creating S3 objects through terraform so we are not checking ACL of bucket objects

    """

    def __init__(self):
        name = "Ensure Write access is blocked on S3 bucket"
        id = "CKV_AWS_STORAGE_0002"
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
        #     )

        aws_s3_bucket_list: list[CustomVertex] = filter_nodes_by_resource_type(graph, str(conf["__address__"]), [AWS_S3_BUCKET])

        for custom_vertex in aws_s3_bucket_list:
            s3_bucket_attributes = custom_vertex.node_data
            # s3_bucket_attributes = aws_s3_bucket.attributes()
            acl = s3_bucket_attributes.get('acl')
            if acl and acl.lower() == "public-read-write":
                return CheckResult.FAILED

        return result


check = S3BlockPublicWrite()
