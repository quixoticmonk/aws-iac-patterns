#!/usr/bin/env python3
import os

from aws_cdk.core import Stack, App, Construct
from infra.kendra_construct import KendraConstruct

app = App()


class KendraStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, context: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        KendraConstruct(self, construct_id, context)


KendraStack(app, "kendrastack", "kendra")
app.synth()
