#!/usr/bin/env python3
from aws_cdk import core

from infra.eks_stack import EksStack

app = core.App()
EksStack(app, "EksStack", "cluster_config")

app.synth()
