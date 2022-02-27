from aws_cdk.core import Stack, Construct, RemovalPolicy
from aws_cdk.aws_eks import KubernetesVersion, Cluster, AwsAuth
from aws_cdk.aws_ec2 import InstanceSize, InstanceType, InstanceClass
from aws_cdk.aws_iam import Role
from aws_cdk.aws_kms import Key


class EksStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, context: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        context: dict = dict(self.node.try_get_context(context))

        self.secret_key = Key(
            self,
            f"{context['prefix']}-key",
            enabled=True,
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
            description="Key created for envelope encryption")

        self.eks_cluster = Cluster(
            self,
            f"{context['prefix']}-cluster",
            cluster_name=f"{context['prefix']}-cluster",
            version=KubernetesVersion.V1_21,
            default_capacity=context["capacity"],
            default_capacity_instance=InstanceType.of(
                InstanceClass.BURSTABLE3, InstanceSize.SMALL),
            output_cluster_name=True,
            output_config_command=True,
            secrets_encryption_key=self.secret_key
        )

        self.master_role = Role.from_role_arn(self, f"{context['prefix']}-master-role",
                                              role_arn=context['auth_role_arn'])

        AwsAuth(self, f"{context['prefix']}-aws-auth", cluster=self.eks_cluster).add_masters_role(role=self.master_role)
