"""
Kendra construct to deploy the following resources:
* Kendra index
* Kendra S3 datasource
* Kendra roles for data source and index
* APi gateway , lambda stack for queries
* Lambda for provider and location indexing
* Lambda layers for external dependencies
"""
import json
import os
import subprocess

from aws_cdk.aws_apigateway import LambdaIntegration, ConnectionType, \
    PassthroughBehavior, MethodResponse, IntegrationResponse, RestApi, DomainName, SecurityPolicy, BasePathMapping
from aws_cdk.aws_apigateway import Resource
from aws_cdk.aws_certificatemanager import Certificate
from aws_cdk.aws_cloudwatch_actions import SnsAction
from aws_cdk.aws_events import Rule, Schedule
from aws_cdk.aws_events_targets import LambdaFunction
from aws_cdk.aws_iam import Role, PolicyDocument, ServicePrincipal, Effect, PolicyStatement, ManagedPolicy, Policy
from aws_cdk.aws_kendra import CfnIndex, CfnDataSource
from aws_cdk.aws_lambda import Function, Runtime, Code, VersionOptions, LayerVersion
from aws_cdk.aws_s3 import Bucket, BlockPublicAccess, BucketEncryption
from aws_cdk.aws_sns import Topic, Subscription, SubscriptionProtocol
from aws_cdk.aws_wafregional import CfnWebACLAssociation
from aws_cdk.core import Construct, Aws, RemovalPolicy, Duration
from cdk_watchful import Watchful
from aws_cdk.aws_kms import Key

from infra.apigateway_lambda_construct import ApiGatewayLambdaConstruct
from .utilities import get_removal_policy, get_log_retention_days


class KendraConstruct(Construct):
    """
    returns the instance of a Kendra construct
    """

    def __init__(self, scope: Construct,
                 construct_id: str, stage: str, context: str, distribution_host: str, **kwargs) -> None:
        """
        Kendra construct to deploy the following resources:
        * Kendra index
        * Kendra S3 datasource
        * Kendra roles for data source and index
        * APi gateway , lambda stack for queries
        * Lambda for provider and location indexing
        * Lambda layers for external dependencies
        """
        super().__init__(scope, construct_id, **kwargs)

        context: dict = dict(self.node.try_get_context(context))
        self.prefix: str = context['project_name'].lower()
        api_lambda_construct: Construct = ApiGatewayLambdaConstruct(self, f"{self.prefix}kendraqueryapi",
                                                                    "api", "kendra")
        self.rest_api: RestApi = api_lambda_construct.main_api
        self.lambda_fn: Function = api_lambda_construct.main_function
        self.lambda_fn.add_layers(self.create_dependencies_layer(
            f"{context['resource_prefix']}-lambda", context["lambda_path"])
        )
        self.lambda_fn.role.add_managed_policy(
            policy=ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="AmazonKendraFullAccess")
        )

        self.api_resource: Resource = api_lambda_construct.root_resource
        self.api_resource.add_cors_preflight(allow_origins=["*"])

        # API Gateway Custom Domain
        if stage in ["live-preview", "prod"]:
            rest_api_custom_domain = self.create_apigw_custom_domain(context[f"apigw_{stage}_custom_domain"],
                                                                     context[f"apigw_{stage}_certificate"],
                                                                     "kendra", stage)
            self.create_apigw_mapping(rest_api_custom_domain)

        with open('infra/kendra_attr.json', 'r') as file:
            self.document_metadata_config = json.loads(file.read())

        self.kendra_edition: str = "ENTERPRISE_EDITION" if stage in [
            "live-preview", "prod"] else "DEVELOPER_EDITION"

        self.kendra_instance_role = self.create_kendra_index_role(stage)
        self.kendra_index: CfnIndex = CfnIndex(self, f"{self.prefix}-kendra-{stage}-index",
                                               edition=self.kendra_edition, name=f"{self.prefix}-kendra-{stage}-index",
                                               description=f"{self.prefix}-kendra-index",
                                               role_arn=self.kendra_instance_role.role_arn,
                                               document_metadata_configurations=self.document_metadata_config
                                               )

        self.lambda_fn.add_environment(key="INDEX_ID", value=self.kendra_index.attr_id)
        self.lambda_fn.add_environment(key="PAGE_SIZE", value=context["query_page_size"])

        # s3 data source
        self.kendra_data_source_instance_role: Role = Role(self,
                                                           f'{self.prefix}-kendra-datasource-{stage}',
                                                           role_name=f'{self.prefix}-kendra-datasource-{stage}',
                                                           assumed_by=ServicePrincipal('kendra.amazonaws.com'))

        self.kendra_data_source_instance_role.add_to_policy(PolicyStatement(
            effect=Effect.ALLOW,
            actions=[
                'kendra:BatchPutDocument',
                'kendra:BatchDeleteDocument',
            ],
            resources=[self.kendra_index.attr_arn]
        ))

        self.s3_provider_source: Bucket = self.create_source_bucket(stage, "provider")
        self.s3_locations_source: Bucket = self.create_source_bucket(stage, "locations")

        self.s3_provider_source.grant_read(self.kendra_data_source_instance_role)
        self.s3_locations_source.grant_read(self.kendra_data_source_instance_role)

        self.kendra_s3_data_provider_source: CfnDataSource = self.create_s3_data_source(
            stage, "provider",
            self.kendra_index.attr_id, self.s3_provider_source.bucket_name,
            self.kendra_data_source_instance_role.role_arn
        )
        self.kendra_s3_data_locations_source: CfnDataSource = self.create_s3_data_source(
            stage, "locations",
            self.kendra_index.attr_id, self.s3_locations_source.bucket_name,
            self.kendra_data_source_instance_role.role_arn
        )

        self.kendra_providers_lambda: Function = self.create_lambda(context["provider_handler"],
                                                                    context["provider_handler_path"],
                                                                    context["log_removal_policy"],
                                                                    f"{self.prefix}-providers",
                                                                    context)

        self.providers_schedule: Rule = self.create_event_rule(
            "providers", Schedule.cron(minute="01", hour="04", month="*",
                                       day="*", year="*")
        )
        self.providers_schedule.add_target(target=LambdaFunction(handler=self.kendra_providers_lambda))
        # Defines the environmental variable to be used
        self.kendra_providers_lambda.add_environment('FAD_URL', context["FAD_URL"])
        self.kendra_providers_lambda.add_environment("S3_DATA_SOURCE_BUCKET_NAME", self.s3_provider_source.bucket_name)
        self.kendra_providers_lambda.add_environment("INDEX_ID", value=self.kendra_index.attr_id)
        self.kendra_providers_lambda.add_environment("DATASOURCE_ID", self.kendra_s3_data_provider_source.attr_id)
        self.add_s3_kendra_permission_to_lambda_role(self.kendra_providers_lambda)
        self.add_invoke_policy(self.kendra_providers_lambda, "providers")

        self.kendra_locations_lambda: Function = self.create_lambda(context["location_handler"],
                                                                    context["location_handler_path"],
                                                                    context["log_removal_policy"],
                                                                    f"{self.prefix}-locations",
                                                                    context)
        self.locations_schedule: Rule = self.create_event_rule(
            "locations", Schedule.cron(minute="01", hour="04", month="*",
                                       day="*", year="*")
        )
        self.locations_schedule.add_target(target=LambdaFunction(handler=self.kendra_locations_lambda))
        # Defines the environmental variable to be used
        self.kendra_locations_lambda.add_environment("FAD_URL", context["FAD_URL"])
        self.kendra_locations_lambda.add_environment("S3_DATA_SOURCE_BUCKET_NAME", self.s3_locations_source.bucket_name)
        self.kendra_locations_lambda.add_environment("INDEX_ID", value=self.kendra_index.attr_id)
        self.kendra_locations_lambda.add_environment("DATASOURCE_ID", self.kendra_s3_data_locations_source.attr_id)
        self.add_s3_kendra_permission_to_lambda_role(self.kendra_locations_lambda)
        self.add_invoke_policy(self.kendra_locations_lambda, "locations")

        # Webcrawler data source creation
        self.wc_healthbeat_source = self.create_crawler_data_source(context, "healthbeat", stage, distribution_host)
        self.wc_site_source = self.create_crawler_data_source(context, "shorg", stage, distribution_host)

        # Create providers, locations & pages endpoint
        self.create_api_pagetype_endpoint(
            context, "providers",
            self.rest_api, self.kendra_index.attr_id, self.wc_site_source.attr_id)
        self.create_api_pagetype_endpoint(
            context, "locations",
            self.rest_api, self.kendra_index.attr_id, self.wc_site_source.attr_id)
        self.create_api_pagetype_endpoint(
            context, "pages",
            self.rest_api, self.kendra_index.attr_id, self.wc_site_source.attr_id)
        self.topic_key = Key.from_lookup(self, "kms_key", alias_name="alias/aws/sns")
        # Watchful dashboard and alarm for Kendra - Lambda Functions
        watchful_kendra = self.call_watchful_kendra(context, stage, self.topic_key)
        # Watchful dashboard and alarm for API GW
        watchful_api = self.call_watchful_apigw(context, stage, self.topic_key)
        self.call_watchful_apigw_dashboard(watchful_api)
        watchful_kendra.watch_lambda_function(title="Kendra_DataSource_Providers", fn=self.kendra_providers_lambda)
        watchful_kendra.watch_lambda_function(title="Kendra_DataSource_Locations", fn=self.kendra_locations_lambda)

        # thesaurus

        self.create_kendra_thesaurus(self.kendra_index, self.s3_locations_source, context)

    def create_waf_association_apigw(self, context, stage):
        """
        associates the APIGW with a WAF rule
        """
        CfnWebACLAssociation(self, f"APIGW-{stage}-WAF", web_acl_id=context[f"web_acl_apigw_id_{stage}"],
                             resource_arn=f"arn:aws:apigateway:us-east-1::/"
                                          f"restapis/{self.rest_api.rest_api_id}/"
                                          f"stages/{self.rest_api.deployment_stage.stage_name}")

    def create_apigw_mapping(self, rest_api_custom_domain):
        """
        Creates the API GW custom mapping
        """
        BasePathMapping(self, f"{self.prefix}-mapping", domain_name=rest_api_custom_domain, rest_api=self.rest_api)

    def create_kendra_thesaurus(self, kendra_index, locations_source, context: dict):
        """
        Create a thesaurus function with shorg synonyms
        """
        thesaurus_fn = Function(self, "id", handler=context["thesaurus_handler"],
                                runtime=Runtime.PYTHON_3_8,
                                code=Code.from_asset(context["thesaurus_handler_path"], ),
                                function_name="create_thesaurus_fn",
                                timeout=Duration.minutes(15)
                                )

        thesaurus_schedule: Rule = self.create_event_rule(
            "thesaurus", Schedule.cron(minute="0", hour="4", month="*",
                                       day="1", year="*")
        )
        thesaurus_schedule.add_target(target=LambdaFunction(handler=thesaurus_fn))
        thesaurus_fn.node.add_dependency(kendra_index)
        thesaurus_fn.role.add_managed_policy(
            policy=ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="AmazonKendraFullAccess")
        )
        lambda_policy_statement = PolicyStatement(
            actions=["s3:List*", "s3:Get*", "s3:Put*"],
            effect=Effect.ALLOW,
            resources=[locations_source.bucket_arn, locations_source.bucket_arn + "/*"]
        )
        thesaurus_fn.role.add_managed_policy(policy=ManagedPolicy.from_aws_managed_policy_name(
            managed_policy_name="AmazonS3FullAccess"))
        kendra_synonym_role = Role(
            self,
            "shorg-create-thesaurus-lambda-role",
            description="Role for codebuild for CI",
            assumed_by=ServicePrincipal(service="kendra.amazonaws.com"),
            role_name="shorg-create-thesaurus-kendra-role",
            inline_policies={
                "thesaurus_lambda_policy": PolicyDocument(
                    statements=[lambda_policy_statement])
            },
            managed_policies=[ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="AmazonKendraFullAccess")]
        )
        thesaurus_fn.add_environment("BUCKET_NAME", locations_source.bucket_name)
        thesaurus_fn.add_environment("BUCKET_KEY", "synonyms/shorg_synonyms.txt")
        thesaurus_fn.add_environment("INDEX_ID", kendra_index.attr_id)
        thesaurus_fn.add_environment("ROLE_ARN", kendra_synonym_role.role_arn)

    def call_watchful_apigw_dashboard(self, watchful_api):
        """
        provisions a watchful dashboard for API Gateway
        """
        watchful_api.watch_api_gateway(title="API Gateway Dashboard", rest_api=self.api_resource.rest_api,
                                       cache_graph=True)

    def call_watchful_apigw(self, context, stage, topic_key):
        """
        provisions the watchful cloudwatch alarms for API Gateway
        """

        cw_apigw_topic = Topic(self, "APIGWTopic", topic_name=f"cw-alarm-apigw-{stage}", master_key=topic_key)
        Subscription(self, "APIGWSub", topic=cw_apigw_topic, protocol=SubscriptionProtocol.EMAIL,
                     endpoint=context['cw_apigw_alarm_email_dest'])
        SnsAction(topic=cw_apigw_topic)
        watchful_api = Watchful(
            self,
            "Watchful_APIGW",
            dashboard_name=f"shorg-{stage}-api_gw-dashboard",
            alarm_sns=cw_apigw_topic)
        return watchful_api

    def call_watchful_kendra(self, context, stage, topic_key):
        """
        provisions the watchful cloudwatch alarms for Amazon Kendra
        """
        cw_kendra_topic = Topic(self, "KendraTopic", topic_name=f"cw-alarm-kendra-{stage}", master_key=topic_key)
        Subscription(self, "KendraSub", topic=cw_kendra_topic, protocol=SubscriptionProtocol.EMAIL,
                     endpoint=context['cw_kendra_alarm_email_dest'])
        SnsAction(topic=cw_kendra_topic)
        watchful_kendra = Watchful(
            self,
            "Watchful_Kendra",
            dashboard_name=f"shorg-{stage}-kendra_datasource-dashboard",
            alarm_sns=cw_kendra_topic)
        return watchful_kendra

    def create_api_pagetype_endpoint(self, context,
                                     page_type: str, rest_api: RestApi,
                                     index_id, data_source_id):
        """
        creates the necessary endpoints and integrate with the lambda required
        """
        api_fn: Function = self.create_lambda(context[f"api_{page_type}_handler"],
                                              context[f"api_{page_type}_path"],
                                              context["log_removal_policy"],
                                              f"{self.prefix}-{page_type}-query",
                                              context)

        api_fn.role.add_managed_policy(
            policy=ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="AmazonKendraFullAccess")
        )

        if page_type == "pages":
            api_fn.add_environment("DATA_SOURCE_ID", data_source_id)

        api_fn.add_environment("INDEX_ID", index_id)
        api_fn.add_environment("PAGE_SIZE", context["query_page_size"])
        api_fn.add_environment("MAX_SUGGESTIONS", context["kendra_query_suggestion_count"])
        api_page_resource = rest_api.root.add_resource(f"{page_type}")
        api_page_resource.add_cors_preflight(allow_origins=["*"])
        api_page_resource.add_method(
            http_method="GET",
            integration=self.create_lambda_integration(api_fn),
            api_key_required=True,
            method_responses=[
                MethodResponse(
                    status_code="200"
                )
            ]
        )

    @staticmethod
    def create_lambda_integration(lambda_fn: Function) -> LambdaIntegration:
        """
        returns lambda integration with the integration response for 200
        """
        return LambdaIntegration(
            handler=lambda_fn,
            allow_test_invoke=True,
            proxy=True,
            connection_type=ConnectionType.INTERNET,
            passthrough_behavior=PassthroughBehavior.WHEN_NO_TEMPLATES,
            timeout=Duration.seconds(20),
            integration_responses=[
                IntegrationResponse(
                    status_code="200"
                )
            ]
        )

    def create_crawler_data_source(self, context: dict, ds_type: str, stage: str, distribution_host: str):
        """
        Creating a datasource with webcrawler as the type
        """
        if ds_type in ["healthbeat"]:
            site_map_environs = context[f"sitemap_{ds_type}"]
        else:
            site_map_environs = [f"https://{context[f'sitemap_{ds_type}']}/{context['sitemap_uri']}"] if stage in [
                "prod"] else \
                [f"https://{distribution_host}/{context['sitemap_uri']}"]

        return CfnDataSource(self,
                             f"shorg-wc-{ds_type}", index_id=self.kendra_index.attr_id,
                             type="WEBCRAWLER",
                             name=f"shorg-wc-{ds_type}",
                             description=f"Webcrawler for the {ds_type}",
                             role_arn=self.kendra_data_source_instance_role.role_arn,
                             schedule=context[f"schedule_{ds_type}"],
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
                                     # url_exclusion_patterns=
                                     # url_inclusion_patterns=
                                 )
                             )
                             )

    def create_event_rule(self, data_type, schedule):
        """
        returns an event rule for S3 data sources
        """
        return Rule(self, f"{data_type}-schedule",
                    description=f"Event trigger for {data_type} data refresh",
                    enabled=True,
                    rule_name=f"{data_type}-schedule",
                    schedule=schedule
                    )

    def create_s3_data_source(self, stage: str,
                              data_type: str, index_id,
                              source_bucket_name, data_source_role_arn):
        """
        returns an S3 data source
        """
        return CfnDataSource(
            self, f"{self.prefix}-kendra-s3-{data_type}-datasource-{stage}",
            name=f"{self.prefix}-kendra-s3-{data_type}-datasource-{stage}",
            index_id=index_id,
            type="S3",
            data_source_configuration=CfnDataSource.DataSourceConfigurationProperty(
                s3_configuration=CfnDataSource.S3DataSourceConfigurationProperty(
                    bucket_name=source_bucket_name
                )
            ),
            role_arn=data_source_role_arn,
            schedule=""
        )

    def create_source_bucket(self, stage,
                             data_type):
        """
        returns a source bucket reference for data source
        """
        return Bucket(self, f"{self.prefix}-kendra-s3-{data_type}-source-{stage}",
                      bucket_name=f"{self.prefix}-kendra-s3-{data_type}-source-{stage}",
                      block_public_access=BlockPublicAccess.BLOCK_ALL,
                      removal_policy=RemovalPolicy.DESTROY,
                      auto_delete_objects=True,
                      encryption=BucketEncryption.S3_MANAGED,
                      enforce_ssl=True
                      )

    def add_invoke_policy(self, function: Function, category: str) -> None:
        """
        Updates the lambda role with a permission to invoke itself and place CloudWatch data
        """
        Policy(self, f"{category}-lambda-policy",
               policy_name=f"{category}-lambda-policy",
               statements=[
                   PolicyStatement(
                       actions=["lambda:InvokeFunction"],
                       resources=[f"{function.function_arn}"]
                   ),
                   PolicyStatement(
                       actions=[
                           "cloudwatch:GetMetricStatistics",
                           "cloudwatch:ListMetrics",
                           "cloudwatch:PutMetricData",
                       ],
                       resources=["*"]
                   )
               ]).attach_to_role(function.role)

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

    def create_kendra_index_role(self, stage):
        """
        returns a role to be used for kendra index
        """
        return Role(
            self, f"{self.prefix}-kendra-servicerole",
            role_name=f"{self.prefix}-kendra-servicerole-{stage}",
            description=f"{self.prefix}-kendra-ServiceRole-{stage}",
            assumed_by=ServicePrincipal("kendra.amazonaws.com"),
            inline_policies={
                "KendraAllowMetricObject": self.create_allow_metrics_policy(),
                "KendraAllowLogObject": self.create_kendra_allow_log_policy(),
                "KendraAllowLogStreamsObject": self.create_kendra_allow_logstreams_policy()
            },
            managed_policies=[ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="CloudWatchLogsFullAccess")]
        )

    def create_lambda(self, handler: str,
                      handler_path: str, removal_policy: str,
                      prefix: str, context: dict) -> Function:
        """returns a function with the user inputs"""
        return Function(
            self,
            f"{prefix}-lambda",
            function_name=f"{prefix}-lambda",
            runtime=Runtime.PYTHON_3_8,
            handler=handler,
            code=Code.from_asset(handler_path),
            current_version_options=VersionOptions(
                removal_policy=get_removal_policy(removal_policy),
                retry_attempts=0,
                description=f"{prefix}-lambda",
            ),
            timeout=Duration.seconds(context["lambda_timeout_in_seconds"]),
            memory_size=context["index_memory"],
            layers=[
                self.create_dependencies_layer(f"{prefix}-lambda", handler_path)
            ],
            log_retention=get_log_retention_days(context["kendra_lambda_log_retention"])
        )

    @staticmethod
    def add_s3_kendra_permission_to_lambda_role(lambda_fn: Function):
        """
        Adds the S3/Kendra access to the lambda roles
        """

        lambda_fn.role.add_managed_policy(
            policy=ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="AmazonKendraFullAccess")
        )
        lambda_fn.role.add_managed_policy(
            policy=ManagedPolicy.from_aws_managed_policy_name(
                managed_policy_name="AmazonS3FullAccess")
        )

    def create_dependencies_layer(self, function_name: str, handler_path: str) -> LayerVersion:
        """
        returns a lambda layer to be used for the lambda deployments with external dependencies
        """
        requirements_file = f'{handler_path}/requirements.txt'
        output_dir = f'../.build/{function_name}'

        if not os.environ.get('SKIP_PIP'):
            subprocess.check_call(
                f'pip install -r {requirements_file} -t {output_dir}/python'.split()
            )
        layer_id = f'{function_name}-dependencies'
        layer_code = Code.from_asset(output_dir)
        return LayerVersion(self, layer_id, code=layer_code)

    def create_apigw_custom_domain(self, cust_domain_name: str, cert_arn: str, prefix: str, stage: str) -> DomainName:
        """
        provisions a APIGW custom domain and certificate mapping
        """
        return DomainName(
            self,
            f"{prefix}-cust-domain",
            domain_name=cust_domain_name,
            certificate=Certificate.from_certificate_arn(self, f"{stage}-apigwcert",
                                                         certificate_arn=cert_arn),
            security_policy=SecurityPolicy.TLS_1_2
        )
