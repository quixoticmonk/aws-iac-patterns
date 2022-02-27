from aws_cdk.core import Stack, Construct, RemovalPolicy
from aws_cdk.aws_eks import KubernetesVersion, Cluster, AwsAuth, EndpointAccess, CapacityType, NodegroupAmiType
from aws_cdk.aws_ec2 import InstanceSize, InstanceType, InstanceClass, SubnetType, SubnetSelection
from aws_cdk.aws_iam import Role, ServicePrincipal, ManagedPolicy, CompositePrincipal, \
    AccountRootPrincipal, PolicyStatement, Effect
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

        self.cluster_svc_role = Role(
            self,
            f"{context['prefix']}-cluster-service-role",
            assumed_by=ServicePrincipal("eks.amazonaws.com"),
            managed_policies=[
                ManagedPolicy.from_aws_managed_policy_name("AmazonEKSClusterPolicy"),
                ManagedPolicy.from_aws_managed_policy_name("AmazonEKS_CNI_Policy"),
                ManagedPolicy.from_aws_managed_policy_name("AmazonEKSVPCResourceController")
            ]
        )

        self.node_role = Role(
            self,
            f"{context['prefix']}-node-role",
            assumed_by=ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                ManagedPolicy.from_aws_managed_policy_name("AmazonEKSWorkerNodePolicy"),
                ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryReadOnly"),
                ManagedPolicy.from_aws_managed_policy_name("AmazonEKS_CNI_Policy"),
                ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
            ]
        )

        self.cluster_admin_role = Role(
            self,
            f"{context['prefix']}-cluster-admin-role",
            assumed_by=CompositePrincipal(
                AccountRootPrincipal(),
                ServicePrincipal("ec2.amazonaws.com")
            )
        )
        self.cluster_admin_role.add_to_policy(
            PolicyStatement(
                effect=Effect.ALLOW,
                actions=["eks:DescribeCluster"],
                resources=["*"]
            )
        )

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
            secrets_encryption_key=self.secret_key,
            role=self.cluster_svc_role,
            masters_role=self.cluster_admin_role,
            endpoint_access=EndpointAccess.PUBLIC
        )

        self.eks_cluster.add_nodegroup_capacity(
            f"{context['prefix']}-ng",
            nodegroup_name=f"{context['prefix']}-ng",
            instance_types=[InstanceType("t3.medium")],
            disk_size=20,
            min_size=1,
            max_size=6,
            desired_size=2,
            subnets=SubnetSelection(
                subnet_type=SubnetType.PUBLIC),
            ami_type=NodegroupAmiType.AL2_X86_64,
            capacity_type=CapacityType.ON_DEMAND,
            node_role=self.node_role
        )

        self.master_role = Role.from_role_arn(self, f"{context['prefix']}-master-role",
                                              role_arn=context['auth_role_arn'])

        AwsAuth(self, f"{context['prefix']}-aws-auth", cluster=self.eks_cluster).add_masters_role(role=self.master_role)
