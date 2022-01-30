import json
from aws_cdk.core import Construct, Stack, Duration, RemovalPolicy, Aws
from aws_cdk.aws_kendra import CfnIndex, CfnDataSource
from aws_cdk.aws_iam import Role, ServicePrincipal, PolicyDocument, PolicyStatement, Effect, ManagedPolicy



class KendraConstruct(Construct):
    """
    returns an instance of the kendra construct
    """
    def __init__(self, scope: Construct, construct_id:str, context: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        context:dict = dict(self.node.try_get_context(context))
        self.prefix: str = context['project_name'].lower()

        self.kendra_edition: str = "ENTERPRISE_EDITION"

        with open('infra/kendra_attributes.json', 'r') as file:
            self.document_metadata_config = json.loads(file.read())

        self.kendra_instance_role = self.create_kendra_index_role()
        self.kendra_index: CfnIndex = CfnIndex(
            self, f"{self.prefix}-kendra-index",
            edition=self.kendra_edition, name=f"{self.prefix}-kendra-index",
            description="Kendra index",
            role_arn=self.kendra_instance_role.role_arn,
            document_metadata_configurations=self.document_metadata_config
        )


        # s3 data source
        self.kendra_data_source_instance_role: Role = Role(self,
                                                           f'{self.prefix}-kendra-datasource-role',
                                                           role_name=f'{self.prefix}-kendra-datasource-role',
                                                           assumed_by=ServicePrincipal('kendra.amazonaws.com'))

        self.kendra_data_source_instance_role.add_to_policy(PolicyStatement(
            effect=Effect.ALLOW,
            actions=[
                'kendra:BatchPutDocument',
                'kendra:BatchDeleteDocument',
            ],
            resources=[self.kendra_index.attr_arn]
        ))


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
            assumed_by=ServicePrincipal("kendra.amazonaws.com"),
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
                             description=f"Webcrawler data source",
                             role_arn=self.kendra_data_source_instance_role.role_arn,
                             schedule=context[f"crawler_schedule"],
                             data_source_configuration=CfnDataSource.DataSourceConfigurationProperty(
                                 web_crawler_configuration=CfnDataSource.WebCrawlerConfigurationProperty(
                                     urls=CfnDataSource.WebCrawlerUrlsProperty(
                                         site_maps_configuration=CfnDataSource.WebCrawlerSiteMapsConfigurationProperty(
                                             site_maps=site_map_environs
                                         )),
                                     crawl_depth=context["crawldepth"],
                                     max_content_size_per_page_in_mega_bytes=context["max_content_size_per_page_in_mega_bytes"],
                                     max_links_per_page=context["max_links_per_page"],
                                     max_urls_per_minute_crawl_rate=context["max_urls_per_minute_crawl_rate"]
                                 )
                             )
                             )