from aws_cdk.aws_certificatemanager import Certificate
from aws_cdk.aws_cloudfront import OriginAccessIdentity, Distribution, \
    HttpVersion, PriceClass, SecurityPolicyProtocol, BehaviorOptions, \
    AllowedMethods, ViewerProtocolPolicy, EdgeLambda, LambdaEdgeEventType, ResponseHeadersPolicy, \
    ResponseSecurityHeadersBehavior, ResponseHeadersContentSecurityPolicy, \
    ResponseHeadersContentTypeOptions, ResponseHeadersFrameOptions, \
    ResponseHeadersReferrerPolicy, HeadersReferrerPolicy, ResponseHeadersStrictTransportSecurity, \
    ResponseHeadersXSSProtection, HeadersFrameOption, ResponseCustomHeadersBehavior, ResponseCustomHeader
from aws_cdk.aws_cloudfront.experimental import EdgeFunction
from aws_cdk.aws_cloudfront_origins import S3Origin
from aws_cdk.aws_iam import PolicyStatement, CanonicalUserPrincipal
from aws_cdk.aws_lambda import VersionOptions, Runtime, Code
from aws_cdk.aws_logs import RetentionDays
from aws_cdk.aws_s3 import Bucket, BucketEncryption
from aws_cdk.core import Construct, RemovalPolicy, Stack, CfnOutput, Duration


class StaticSiteStack(Stack):
    """
    returns an instance of the kendra construct
    """

    def __init__(self, scope: Construct, construct_id: str, context: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        context: dict = dict(self.node.try_get_context(context))
        self.prefix: str = context['project_name'].lower()

        self.source_bucket = self.create_bucket()
        self.cfront_oai = self.create_origin_access_identity()
        self.source_bucket.add_to_resource_policy(
            PolicyStatement(
                actions=["s3:GetObject"],
                resources=[self.source_bucket.arn_for_objects("*")],
                principals=[
                    CanonicalUserPrincipal(
                        self.cfront_oai.cloud_front_origin_access_identity_s3_canonical_user_id
                    )
                ]
            )
        )

        self.response_headers_policy = ResponseHeadersPolicy(
            self,
            "response_header_policy",
            comment="Response header policy",
            response_headers_policy_name="response_headers",
            custom_headers_behavior=ResponseCustomHeadersBehavior(
                custom_headers=[
                    ResponseCustomHeader(
                        header="Permissions-Policy",
                        value="accelerometer=(), camera=(), geolocation=(), "
                              "gyroscope=(), magnetometer=(), microphone=(), "
                              "payment=(), usb=(), interest-cohort=()",
                        override=True),
                ]
            ),
            security_headers_behavior=ResponseSecurityHeadersBehavior(
                content_security_policy=ResponseHeadersContentSecurityPolicy(
                    content_security_policy="",
                    override=True),
                content_type_options=ResponseHeadersContentTypeOptions(override=True),
                frame_options=ResponseHeadersFrameOptions(frame_option=HeadersFrameOption.SAMEORIGIN,
                                                          override=True),
                referrer_policy=ResponseHeadersReferrerPolicy(
                    referrer_policy=HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override=True),
                strict_transport_security=ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=Duration.seconds(31536000), include_subdomains=False, override=True),
                xss_protection=ResponseHeadersXSSProtection(protection=True, mode_block=True,
                                                            override=True
                                                            )
            )
        )
        self.cfront_dist = self.create_distribution(context)

        self.sourcebucketname = CfnOutput(self, "sourceBucketName", value=self.source_bucket.bucket_name)

    def create_distribution(self, context):
        return Distribution(
            self, "cfront_dist",
            enabled=True,
            comment="staticsite",
            http_version=HttpVersion.HTTP2,
            enable_logging=False,
            default_root_object="index.html",
            price_class=PriceClass.PRICE_CLASS_100,
            enable_ipv6=False,
            domain_names=context["domain_names"],
            minimum_protocol_version=SecurityPolicyProtocol.TLS_V1_2_2021,
            default_behavior=self.get_default_behavior(self.source_bucket, self.cfront_oai, context),
            certificate=Certificate.from_certificate_arn(
                self, "site-cert",
                certificate_arn=context["cert_arn"]
            ),
        )

    def get_default_behavior(self, source_bucket, oai, context):
        redirect_uri_fn = self.create_lambda_edge_fn(
            context["lambda_edge_handler"],
            context["lambda_edge_handler_path"],
            "site-redirect-uri",
            context
        )

        return BehaviorOptions(
            allowed_methods=AllowedMethods.ALLOW_GET_HEAD,
            viewer_protocol_policy=ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            origin=self.get_s3_origin(source_bucket, oai, context),
            compress=True,
            smooth_streaming=False,
            edge_lambdas=[EdgeLambda(
                event_type=LambdaEdgeEventType.VIEWER_REQUEST,
                function_version=redirect_uri_fn.current_version
            )],
            response_headers_policy=self.response_headers_policy
        )

    @staticmethod
    def get_s3_origin(self, oai, context):
        return S3Origin(
            bucket=self,
            origin_path=context["origin_path"],
            origin_access_identity=oai
        )

    def create_bucket(self):
        return Bucket(
            self,
            "static_bucket",
            bucket_name="static_bucket",
            encryption=BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            versioned=False,
            public_read_access=True
        )

    def create_origin_access_identity(self):
        return OriginAccessIdentity(
            self,
            "oai",
            comment="Cloudfront access to S3"
        )

    def create_lambda_edge_fn(self, handler, handler_path, prefix, context):
        return EdgeFunction(
            self,
            f"{prefix}",
            function_name=f"{prefix}",
            description="Edge function for managing redirect uri ",
            runtime=Runtime.NODEJS_12_X,
            handler=handler,
            code=Code.from_asset(handler_path),
            current_version_options=VersionOptions(
                removal_policy=RemovalPolicy.DESTROY,
                retry_attempts=0,
                description=f"{prefix}-edge-lambda"
            ),
            timeout=Duration.seconds(context["lambda_edge_timeout_in_seconds"]),
            memory_size=context["lambda_edge_memory"],
            log_retention=RetentionDays.FIVE_DAYS
        )
