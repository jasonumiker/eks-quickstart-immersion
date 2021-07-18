# CDK to deploy ghost and its dependencies to the cluster created in Event Engine

from aws_cdk import (
    aws_ec2 as ec2,
    aws_rds as rds,
    aws_eks as eks,
    aws_iam as iam,
    core
)
import os
import yaml

class GhostStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Import our existing VPC whose name is EKSClusterStack/VPC
        vpc = ec2.Vpc.from_lookup(self, 'VPC', vpc_name="EKSClusterStack/VPC")

        # Create a Securuty Group for our RDS
        security_group = ec2.SecurityGroup(
            self, "Ghost-DB-SG",
            vpc=vpc,
            allow_all_outbound=True
        )
        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(3306)
        )

        # Create a MySQL RDS
        ghost_rds = rds.DatabaseInstance(
            self, "RDS",
            deletion_protection=False,
            removal_policy=core.RemovalPolicy.DESTROY,
            multi_az=False,
            allocated_storage=20,
            engine=rds.DatabaseInstanceEngine.mysql(
                version=rds.MysqlEngineVersion.VER_8_0_25
            ),
            credentials=rds.Credentials.from_username("root"),
            database_name="ghost",
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO),
            security_groups=[security_group]
        )

        # Import our existing EKS Cluster whose name and other details are in CloudFormation Exports
        eks_cluster = eks.Cluster.from_cluster_attributes(
            self, "cluster",
            cluster_name=core.Fn.import_value("EKSClusterName"),
            open_id_connect_provider=eks.OpenIdConnectProvider.from_open_id_connect_provider_arn(
                self, "EKSClusterOIDCProvider",
                open_id_connect_provider_arn = core.Fn.import_value("EKSClusterOIDCProviderARN")
            ),
            kubectl_role_arn=core.Fn.import_value("EKSClusterKubectlRoleARN"),
            vpc=vpc,
            kubectl_security_group_id=core.Fn.import_value("EKSSGID"),
            kubectl_private_subnet_ids=[vpc.private_subnets[0].subnet_id, vpc.private_subnets[1].subnet_id]
        )

        # Deploy the External Secrets Controller
        # Create the Service Account
        externalsecrets_service_account = eks_cluster.add_service_account(
            "kubernetes-external-secrets",
            name="kubernetes-external-secrets",
            namespace="kube-system"
        )

        # Define the policy in JSON
        externalsecrets_policy_statement_json_1 = {
        "Effect": "Allow",
            "Action": [
                "secretsmanager:GetResourcePolicy",
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret",
                "secretsmanager:ListSecretVersionIds"
            ],
            "Resource": [
                "*"
            ]
        }

        # Add the policies to the service account
        externalsecrets_service_account.add_to_policy(iam.PolicyStatement.from_json(externalsecrets_policy_statement_json_1))

        # Deploy the Helm Chart
        external_secrets_chart = eks_cluster.add_helm_chart(
            "external-secrets",
            chart="kubernetes-external-secrets",
            version="8.2.2",            
            repository="https://external-secrets.github.io/kubernetes-external-secrets/",
            namespace="kube-system",
            values={
                "env": {
                    "AWS_REGION": self.region
                },
                "serviceAccount": {
                    "name": "kubernetes-external-secrets",
                    "create": False
                },
                "securityContext": {
                    "fsGroup": 65534
                }
            }
        )

        # Map in the secret for the ghost DB
        eks_cluster.add_manifest("GhostExternalSecret",{
            "apiVersion": "kubernetes-client.io/v1",
            "kind": "ExternalSecret",
            "metadata": {
                "name": "ghost-database",
                "namespace": "default"
            },
            "spec": {
                "backendType": "secretsManager",
                "data": [
                {
                    "key": ghost_rds.secret.secret_name,
                    "name": "password",
                    "property": "password"
                },
                {
                    "key": ghost_rds.secret.secret_name,
                    "name": "dbname",
                    "property": "dbname"
                },
                {
                    "key": ghost_rds.secret.secret_name,
                    "name": "host",
                    "property": "host"
                },
                {
                    "key": ghost_rds.secret.secret_name,
                    "name": "username",
                    "property": "username"
                }
                ]
            }
        })

        # Import ghost-deployment.yaml to a dictionary and submit it as a manifest to EKS
        # Read the YAML file
        ghost_deployment_yaml_file = open("ghost-deployment.yaml", 'r')
        ghost_deployment_yaml = yaml.load(ghost_deployment_yaml_file, Loader=yaml.FullLoader)
        ghost_deployment_yaml_file.close()
        #print(ghost_deployment_yaml)
        eks_cluster.add_manifest("GhostDeploymentManifest",ghost_deployment_yaml)

        # Import ghost-service.yaml to a dictionary and submit it as a manifest to EKS
        # Read the YAML file
        ghost_service_yaml_file = open("ghost-service.yaml", 'r')
        ghost_service_yaml = yaml.load(ghost_service_yaml_file, Loader=yaml.FullLoader)
        ghost_service_yaml_file.close()
        #print(ghost_service_yaml)
        eks_cluster.add_manifest("GhostServiceManifest",ghost_service_yaml)

        # Import ghost-ingress.yaml to a dictionary and submit it as a manifest to EKS
        # Read the YAML file
        ghost_ingress_yaml_file = open("ghost-ingress.yaml", 'r')
        ghost_ingress_yaml = yaml.load(ghost_ingress_yaml_file, Loader=yaml.FullLoader)
        ghost_ingress_yaml_file.close()
        #print(ghost_ingress_yaml)
        eks_cluster.add_manifest("GhostIngressManifest",ghost_ingress_yaml)                

app = core.App()
account = os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])
region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
ghost_stack = GhostStack(app, "GhostStack", env=core.Environment(account=account, region=region))
app.synth()