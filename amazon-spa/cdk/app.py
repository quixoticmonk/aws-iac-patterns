#!/usr/bin/env python3

from aws_cdk.core import App, Environment

from infra.s3_cloudfront import StaticSiteStack

app = App()


StaticSiteStack(app, "staticsite", "staticsite", env=Environment(region="us-east-1"))


app.synth()
