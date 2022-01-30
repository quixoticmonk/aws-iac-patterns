"""
Kendra construct to deploy the following resources:
* Kendra index
* Kendra roles for data source and index
* kendra webcrawler data source with sitemap from context json
* A source bucket to hold data
* S3 data source for Kendra
"""

import json
from aws_cdk.aws_iam import Role, ServicePrincipal, PolicyDocument, PolicyStatement, Effect, ManagedPolicy
from aws_cdk.aws_kendra import CfnIndex, CfnDataSource
from aws_cdk.core import Construct, Aws, RemovalPolicy
from aws_cdk.aws_s3 import Bucket, BucketEncryption, BlockPublicAccess

KENDRA_PRINCIPAL = "kendra.amazonaws.com"


class KendraConstruct(Construct):
    """
    returns an instance of the kendra construct
    """

    def __init__(self, scope: Construct, construct_id: str, context: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        context: dict = dict(self.node.try_get_context(context))
        self.prefix: str = context['project_name'].lower()

        with open('infra/kendra_attributes.json', 'r', encoding="utf8") as file:
            self.document_metadata_config = json.loads(file.read())

        self.kendra_instance_role = self.create_kendra_index_role()

        self.kendra_index: CfnIndex = CfnIndex(
            self, f"{self.prefix}-kendra-index",
            edition="ENTERPRISE_EDITION", name=f"{self.prefix}-kendra-index",
            description="Kendra index",
            role_arn=self.kendra_instance_role.role_arn,
            document_metadata_configurations=self.document_metadata_config
        )

        self.kendra_data_source_instance_role: Role = Role(self,
                                                           f'{self.prefix}-kendra-datasource-role',
                                                           role_name=f'{self.prefix}-kendra-datasource-role',
                                                           assumed_by=ServicePrincipal(KENDRA_PRINCIPAL))

        self.kendra_data_source_instance_role.add_to_policy(PolicyStatement(
            effect=Effect.ALLOW,
            actions=[
                'kendra:BatchPutDocument',
                'kendra:BatchDeleteDocument',
            ],
            resources=[self.kendra_index.attr_arn]
        ))

        # s3 data source creation
        self.source_bucket: Bucket = self.create_bucket()
        self.source_bucket.grant_read(self.kendra_data_source_instance_role)

        self.s3_data_source: CfnDataSource = self.create_s3_data_source(
            self.kendra_index.attr_id, self.source_bucket.bucket_name,
            self.kendra_data_source_instance_role.role_arn
        )

        # Webcrawler data source creation
        self.wc_source: CfnDataSource = self.create_crawler_data_source(
            context)

    @staticmethod
    def create_kendra_allow_logstreams_policy() -> PolicyDocument:
        """
        returns a policy document to allow creation of log streams
        """
        return PolicyDocument(
            statements=[
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        'logs:DescribeLogStreams',
                        'logs:CreateLogStream',
                        'logs:PutLogEvents',
                    ],
                    resources=[
                        f"arn:aws:logs:{Aws.REGION}:{Aws.ACCOUNT_ID}:log-group:/aws/kendra/*:log-stream:*",
                    ],
                )
            ]
        )

    @staticmethod
    def create_kendra_allow_log_policy() -> PolicyDocument:
        """
        returns a policy document to allow creation of log groups
        """
        return PolicyDocument(
            statements=[
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=[
                        'logs:DescribeLogGroups',
                        'logs:CreateLogGroup',
                    ],
                    resources=[
                        f"arn:aws:logs:{Aws.REGION}:{Aws.ACCOUNT_ID}:log-group:/aws/kendra/*"
                    ],
                )
            ]
        )

    @staticmethod
    def create_allow_metrics_policy() -> PolicyDocument:
        """
        returns a policy document to allows kendra index sending metrics data to cloudwatch
        """
        return PolicyDocument(
            statements=[
                PolicyStatement(
                    effect=Effect.ALLOW,
                    actions=["cloudwatch:PutMetricData"],
                    resources=["*"],
                    conditions={
                        "StringEquals": {
                            'cloudwatch:namespace': 'AWS/Kendra',
                        }
                    }
                )
            ]
        )

    def create_kendra_index_role(self):
        """
        returns a role to be used for kendra index
        """
        return Role(
            self, f"{self.prefix}-kendra-servicerole",
            role_name=f"{self.prefix}-kendra-servicerole",
            description=f"{self.prefix}-kendra-ServiceRole",
            assumed_by=ServicePrincipal(KENDRA_PRINCIPAL),
            inline_policies={
                "KendraAllowMetricObject": self.create_allow_metrics_policy(),
                "KendraAllowLogObject": self.create_kendra_allow_log_policy(),
                "KendraAllowLogStreamsObject": self.create_kendra_allow_logstreams_policy()
            },
            managed_policies=[ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="CloudWatchLogsFullAccess")]
        )

    def create_crawler_data_source(self, context: dict):
        """
        Creating a datasource with webcrawler as the type
        """
        return CfnDataSource(self,
                             f"{self.prefix}-wc", index_id=self.kendra_index.attr_id,
                             type="WEBCRAWLER",
                             name=f"{self.prefix}-wc",
                             description="Webcrawler data source",
                             role_arn=self.kendra_data_source_instance_role.role_arn,
                             schedule=context["crawler_schedule"],
                             data_source_configuration=CfnDataSource.DataSourceConfigurationProperty(
                                 web_crawler_configuration=CfnDataSource.WebCrawlerConfigurationProperty(
                                     urls=CfnDataSource.WebCrawlerUrlsProperty(
                                         site_maps_configuration=CfnDataSource.WebCrawlerSiteMapsConfigurationProperty(
                                             site_maps=context["sitemap_urls"]
                                         )),
                                     crawl_depth=context["crawl_depth"],
                                     max_content_size_per_page_in_mega_bytes=context[
                                         "max_content_size_per_page_in_mega_bytes"],
                                     max_links_per_page=context["max_links_per_page"],
                                     max_urls_per_minute_crawl_rate=context["max_urls_per_minute_crawl_rate"]
                                 )
                             )
                             )

    def create_s3_data_source(self,
                              index_id,
                              source_bucket_name, data_source_role_arn):
        """
        returns an S3 data source
        """
        return CfnDataSource(
            self, f"{self.prefix}-kendra-s3-datasource",
            name=f"{self.prefix}-kendra-s3-datasource",
            index_id=index_id,
            type="S3",
            data_source_configuration=CfnDataSource.DataSourceConfigurationProperty(
                s3_configuration=CfnDataSource.S3DataSourceConfigurationProperty(
                    bucket_name=source_bucket_name
                )
            ),
            role_arn=data_source_role_arn,
            schedule=""  # setting this to blank to have an ondemand schedule, else match the cron schedule
        )

    def create_bucket(self):
        """
        returns a source bucket reference for data source
        """
        return Bucket(self, f"{self.prefix}-kendra-s3-source-bucket",
                      bucket_name=f"{self.prefix}-kendra-s3-source-bucket",
                      block_public_access=BlockPublicAccess.BLOCK_ALL,
                      removal_policy=RemovalPolicy.DESTROY,
                      auto_delete_objects=True,
                      encryption=BucketEncryption.S3_MANAGED,
                      enforce_ssl=True
                      )
