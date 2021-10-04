"""
Purpose

Create and delete our AWS Managed Prometheus (AMP) since it doesn't yet have CloudFormation support
"""

from aws_cdk import (
    aws_iam as iam,
    aws_logs as logs,
    custom_resources as custom_resources,
    core,
)
import os


class AMPCustomResource(core.Construct):

    def __init__(self, scope: core.Construct, id: str) -> None:
        super().__init__(scope, id)

        lambda_role = iam.Role(self, "LambdaRole",
                               assumed_by=iam.ServicePrincipal(
                                   'lambda.amazonaws.com'),
                               managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                                   "service-role/AWSLambdaBasicExecutionRole")],
                               )

        lambda_policy = custom_resources.AwsCustomResourcePolicy.from_statements([
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["aps:*"],
                resources=["*"]
            )
        ])

        amp_custom_resource = custom_resources.AwsCustomResource(
            scope=self,
            id='AMPCustomResource',
            policy=lambda_policy,
            log_retention=logs.RetentionDays.INFINITE,
            on_create=self.create(),
            on_delete=self.delete(),
            resource_type='Custom::AMP-Workspace'
        )
        self.workspace_id = amp_custom_resource.get_response_field(
            "workspaceId")

    def create(self):
        return custom_resources.AwsSdkCall(
            action='createWorkspace',
            service='Amp',
            physical_resource_id=custom_resources.PhysicalResourceId.from_response(
                response_path="workspaceId")
        )

    def delete(self):
        return custom_resources.AwsSdkCall(
            action='deleteWorkspace',
            service='Amp',
            parameters={
                "workspaceId": custom_resources.PhysicalResourceIdReference()},
        )
