"""
Purpose

Example of how to provision an EKS cluster, create the IAM Roles for Service Accounts (IRSA) mappings,
and then deploy various common cluster add-ons (AWS LB Controller, ExternalDNS, EBS/EFS CSI Drivers,
Cluster Autoscaler, AWS OpenSearch, Prometheus & Grafana, Calico NetworkPolicy enforcement,
OPA Gatekeeper w/example policies, etc.)

NOTE: This pulls many parameters/options for what you'd like from the cdk.json context section.
Have a look there for many options you can change to customise this template for your environments/needs.
"""

from aws_cdk import (
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    aws_opensearchservice as opensearch,
    aws_logs as logs,
    aws_certificatemanager as cm,
    core
)
import os
import yaml

# Import the custom resource to switch on control plane logging from ekslogs_custom_resource.py
from ekslogs_custom_resource import EKSLogsObjectResource
from amp_custom_resource import AMPCustomResource


class EKSClusterStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Either create a new IAM role to administrate the cluster or create a new one
        if (self.node.try_get_context("create_new_cluster_admin_role") == "True"):
            cluster_admin_role = iam.Role(self, "ClusterAdminRole",
                                          assumed_by=iam.CompositePrincipal(
                                              iam.AccountRootPrincipal(),
                                              iam.ServicePrincipal(
                                                  "ec2.amazonaws.com")
                                          )
                                          )
            cluster_admin_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "eks:DescribeCluster"
                ],
                "Resource": "*"
            }
            cluster_admin_role.add_to_policy(
                iam.PolicyStatement.from_json(cluster_admin_policy_statement_json_1))
        else:
            # You'll also need to add a trust relationship to ec2.amazonaws.com to sts:AssumeRole to this as well
            cluster_admin_role = iam.Role.from_role_arn(self, "ClusterAdminRole",
                role_arn="arn:aws:iam::" +
                    core.Fn.ref("AWS::AccountId") + ":role/TeamRole"
            )

        # Either create a new VPC with the options below OR import an existing one by name
        if (self.node.try_get_context("create_new_vpc") == "True"):
            eks_vpc = ec2.Vpc(
                self, "VPC",
                # We are choosing to spread our VPC across 3 availability zones
                max_azs=3,
                # We are creating a VPC that has a /22, 1024 IPs, for our EKS cluster.
                # I am using that instead of a /16 etc. as I know many companies have constraints here
                # If you can go bigger than this great - but I would try not to go much smaller if you can
                # I use https://www.davidc.net/sites/default/subnets/subnets.html to me work out the CIDRs
                cidr=self.node.try_get_context("vpc_cidr"),
                subnet_configuration=[
                    # 3 x Public Subnets (1 per AZ) with 64 IPs each for our ALBs and NATs
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PUBLIC,
                        name="Public",
                        cidr_mask=self.node.try_get_context(
                            "vpc_cidr_mask_public")
                    ),
                    # 3 x Private Subnets (1 per AZ) with 256 IPs each for our Nodes and Pods
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PRIVATE,
                        name="Private",
                        cidr_mask=self.node.try_get_context(
                            "vpc_cidr_mask_private")
                    )
                ]
            )
        else:
            eks_vpc = ec2.Vpc.from_lookup(
                self, 'VPC', vpc_name=self.node.try_get_context("existing_vpc_name"))

        # Create an EKS Cluster
        eks_cluster = eks.Cluster(
            self, "cluster",
            vpc=eks_vpc,
            masters_role=cluster_admin_role,
            # Make our cluster's control plane accessible only within our private VPC
            # This means that we'll have to ssh to a jumpbox/bastion or set up a VPN to manage it
            endpoint_access=eks.EndpointAccess.PRIVATE,
            version=eks.KubernetesVersion.of(
                self.node.try_get_context("eks_version")),
            default_capacity=0
        )

        # Enable control plane logging (via ekslogs_custom_resource.py)
        # This requires a custom resource until that has CloudFormation Support
        # TODO: remove this when no longer required when CF support launches
        EKSLogsObjectResource(
            self, "EKSLogsObjectResource",
            eks_name=eks_cluster.cluster_name,
            eks_arn=eks_cluster.cluster_arn
        )

        # Create the CF exports that let you rehydrate the Cluster object in other stack(s)
        if (self.node.try_get_context("create_cluster_exports") == "True"):
            # Output the EKS Cluster Name and Export it
            core.CfnOutput(
                self, "EKSClusterName",
                value=eks_cluster.cluster_name,
                description="The name of the EKS Cluster",
                export_name="EKSClusterName"
            )
            # Output the EKS Cluster OIDC Issuer and Export it
            core.CfnOutput(
                self, "EKSClusterOIDCProviderARN",
                value=eks_cluster.open_id_connect_provider.open_id_connect_provider_arn,
                description="The EKS Cluster's OIDC Provider ARN",
                export_name="EKSClusterOIDCProviderARN"
            )
            # Output the EKS Cluster kubectl Role ARN
            core.CfnOutput(
                self, "EKSClusterKubectlRoleARN",
                value=eks_cluster.kubectl_role.role_arn,
                description="The EKS Cluster's kubectl Role ARN",
                export_name="EKSClusterKubectlRoleARN"
            )
            # Output the EKS Cluster SG ID
            core.CfnOutput(
                self, "EKSSGID",
                value=eks_cluster.kubectl_security_group.security_group_id,
                description="The EKS Cluster's kubectl SG ID",
                export_name="EKSSGID"
            )

        # Add a Managed Node Group
        # If we enabled spot then use that
        if (self.node.try_get_context("eks_node_spot") == "True"):
            node_capacity_type = eks.CapacityType.SPOT
        # Otherwise give us OnDemand
        else:
            node_capacity_type = eks.CapacityType.ON_DEMAND
        eks_node_group = eks_cluster.add_nodegroup_capacity(
            "cluster-default-ng",
            capacity_type=node_capacity_type,
            desired_size=self.node.try_get_context("eks_node_quantity"),
            max_size=self.node.try_get_context("eks_node_max_quantity"),
            disk_size=self.node.try_get_context("eks_node_disk_size"),
            # The default in CDK is to force upgrades through even if they violate - it is safer to not do that
            force_update=False,
            instance_types=[ec2.InstanceType(
                self.node.try_get_context("eks_node_instance_type"))],
            release_version=self.node.try_get_context("eks_node_ami_version")
        )
        eks_node_group.role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

        # AWS Load Balancer Controller
        if (self.node.try_get_context("deploy_aws_lb_controller") == "True"):
            awslbcontroller_service_account = eks_cluster.add_service_account(
                "aws-load-balancer-controller",
                name="aws-load-balancer-controller",
                namespace="kube-system"
            )

            # Create the PolicyStatements to attach to the role
            # Got the required policy from https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json
            awslbcontroller_policy_document_json = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:CreateServiceLinkedRole",
                            "ec2:DescribeAccountAttributes",
                            "ec2:DescribeAddresses",
                            "ec2:DescribeAvailabilityZones",
                            "ec2:DescribeInternetGateways",
                            "ec2:DescribeVpcs",
                            "ec2:DescribeSubnets",
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeInstances",
                            "ec2:DescribeNetworkInterfaces",
                            "ec2:DescribeTags",
                            "ec2:GetCoipPoolUsage",
                            "ec2:DescribeCoipPools",
                            "elasticloadbalancing:DescribeLoadBalancers",
                            "elasticloadbalancing:DescribeLoadBalancerAttributes",
                            "elasticloadbalancing:DescribeListeners",
                            "elasticloadbalancing:DescribeListenerCertificates",
                            "elasticloadbalancing:DescribeSSLPolicies",
                            "elasticloadbalancing:DescribeRules",
                            "elasticloadbalancing:DescribeTargetGroups",
                            "elasticloadbalancing:DescribeTargetGroupAttributes",
                            "elasticloadbalancing:DescribeTargetHealth",
                            "elasticloadbalancing:DescribeTags"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "cognito-idp:DescribeUserPoolClient",
                            "acm:ListCertificates",
                            "acm:DescribeCertificate",
                            "iam:ListServerCertificates",
                            "iam:GetServerCertificate",
                            "waf-regional:GetWebACL",
                            "waf-regional:GetWebACLForResource",
                            "waf-regional:AssociateWebACL",
                            "waf-regional:DisassociateWebACL",
                            "wafv2:GetWebACL",
                            "wafv2:GetWebACLForResource",
                            "wafv2:AssociateWebACL",
                            "wafv2:DisassociateWebACL",
                            "shield:GetSubscriptionState",
                            "shield:DescribeProtection",
                            "shield:CreateProtection",
                            "shield:DeleteProtection"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:AuthorizeSecurityGroupIngress",
                            "ec2:RevokeSecurityGroupIngress"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateSecurityGroup"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateTags"
                        ],
                        "Resource": "arn:aws:ec2:*:*:security-group/*",
                        "Condition": {
                            "StringEquals": {
                                "ec2:CreateAction": "CreateSecurityGroup"
                            },
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateTags",
                            "ec2:DeleteTags"
                        ],
                        "Resource": "arn:aws:ec2:*:*:security-group/*",
                        "Condition": {
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:AuthorizeSecurityGroupIngress",
                            "ec2:RevokeSecurityGroupIngress",
                            "ec2:DeleteSecurityGroup"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "Null": {
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:CreateLoadBalancer",
                            "elasticloadbalancing:CreateTargetGroup"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:CreateListener",
                            "elasticloadbalancing:DeleteListener",
                            "elasticloadbalancing:CreateRule",
                            "elasticloadbalancing:DeleteRule"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:AddTags",
                            "elasticloadbalancing:RemoveTags"
                        ],
                        "Resource": [
                            "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                            "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                            "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
                        ],
                        "Condition": {
                            "Null": {
                                "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:AddTags",
                            "elasticloadbalancing:RemoveTags"
                        ],
                        "Resource": [
                            "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                            "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                            "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                            "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
                        ]
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:ModifyLoadBalancerAttributes",
                            "elasticloadbalancing:SetIpAddressType",
                            "elasticloadbalancing:SetSecurityGroups",
                            "elasticloadbalancing:SetSubnets",
                            "elasticloadbalancing:DeleteLoadBalancer",
                            "elasticloadbalancing:ModifyTargetGroup",
                            "elasticloadbalancing:ModifyTargetGroupAttributes",
                            "elasticloadbalancing:DeleteTargetGroup"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "Null": {
                                "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:RegisterTargets",
                            "elasticloadbalancing:DeregisterTargets"
                        ],
                        "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "elasticloadbalancing:SetWebAcl",
                            "elasticloadbalancing:ModifyListener",
                            "elasticloadbalancing:AddListenerCertificates",
                            "elasticloadbalancing:RemoveListenerCertificates",
                            "elasticloadbalancing:ModifyRule"
                        ],
                        "Resource": "*"
                    }
                ]
            }

            # Attach the necessary permissions
            awslbcontroller_policy = iam.Policy(
                self, "awslbcontrollerpolicy",
                document=iam.PolicyDocument.from_json(
                    awslbcontroller_policy_document_json)
            )
            awslbcontroller_service_account.role.attach_inline_policy(
                awslbcontroller_policy)

            # Deploy the AWS Load Balancer Controller from the AWS Helm Chart
            # For more info check out https://github.com/aws/eks-charts/tree/master/stable/aws-load-balancer-controller
            awslbcontroller_chart = eks_cluster.add_helm_chart(
                "aws-load-balancer-controller",
                chart="aws-load-balancer-controller",
                version="1.2.7",
                release="awslbcontroller",
                repository="https://aws.github.io/eks-charts",
                namespace="kube-system",
                values={
                    "clusterName": eks_cluster.cluster_name,
                    "region": self.region,
                    "vpcId": eks_vpc.vpc_id,
                    "serviceAccount": {
                        "create": False,
                        "name": "aws-load-balancer-controller"
                    },
                    "replicaCount": 2
                }
            )
            awslbcontroller_chart.node.add_dependency(
                awslbcontroller_service_account)

        # External DNS Controller
        if (self.node.try_get_context("deploy_external_dns") == "True"):
            externaldns_service_account = eks_cluster.add_service_account(
                "external-dns",
                name="external-dns",
                namespace="kube-system"
            )

            # Create the PolicyStatements to attach to the role
            # See https://github.com/kubernetes-sigs/external-dns/blob/master/docs/tutorials/aws.md#iam-policy
            # NOTE that this will give External DNS access to all Route53 zones
            # For production you'll likely want to replace 'Resource *' with specific resources
            externaldns_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "route53:ChangeResourceRecordSets"
                ],
                "Resource": [
                    "arn:aws:route53:::hostedzone/*"
                ]
            }
            externaldns_policy_statement_json_2 = {
                "Effect": "Allow",
                "Action": [
                    "route53:ListHostedZones",
                    "route53:ListResourceRecordSets"
                ],
                "Resource": [
                    "*"
                ]
            }

            # Attach the necessary permissions
            externaldns_service_account.add_to_policy(
                iam.PolicyStatement.from_json(externaldns_policy_statement_json_1))
            externaldns_service_account.add_to_policy(
                iam.PolicyStatement.from_json(externaldns_policy_statement_json_2))

            # Deploy External DNS from the bitnami Helm chart
            # For more info see https://github.com/bitnami/charts/tree/master/bitnami/external-dns
            externaldns_chart = eks_cluster.add_helm_chart(
                "external-dns",
                chart="external-dns",
                version="5.4.7",
                release="externaldns",
                repository="https://charts.bitnami.com/bitnami",
                namespace="kube-system",
                values={
                    "provider": "aws",
                    "aws": {
                        "region": self.region
                    },
                    "serviceAccount": {
                        "create": False,
                        "name": "external-dns"
                    },
                    "podSecurityContext": {
                        "fsGroup": 65534
                    },
                    "replicas": 2
                }
            )
            externaldns_chart.node.add_dependency(externaldns_service_account)

        # AWS EBS CSI Driver
        if (self.node.try_get_context("deploy_aws_ebs_csi") == "True"):
            awsebscsidriver_service_account = eks_cluster.add_service_account(
                "awsebscsidriver",
                name="awsebscsidriver",
                namespace="kube-system"
            )

            # Create the IAM Policy Document
            # For more info see https://github.com/kubernetes-sigs/aws-ebs-csi-driver/blob/master/docs/example-iam-policy.json
            awsebscsidriver_policy_document_json = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateSnapshot",
                            "ec2:AttachVolume",
                            "ec2:DetachVolume",
                            "ec2:ModifyVolume",
                            "ec2:DescribeAvailabilityZones",
                            "ec2:DescribeInstances",
                            "ec2:DescribeSnapshots",
                            "ec2:DescribeTags",
                            "ec2:DescribeVolumes",
                            "ec2:DescribeVolumesModifications"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateTags"
                        ],
                        "Resource": [
                            "arn:aws:ec2:*:*:volume/*",
                            "arn:aws:ec2:*:*:snapshot/*"
                        ],
                        "Condition": {
                            "StringEquals": {
                                "ec2:CreateAction": [
                                    "CreateVolume",
                                    "CreateSnapshot"
                                ]
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DeleteTags"
                        ],
                        "Resource": [
                            "arn:aws:ec2:*:*:volume/*",
                            "arn:aws:ec2:*:*:snapshot/*"
                        ]
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateVolume"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringLike": {
                                "aws:RequestTag/ebs.csi.aws.com/cluster": "true"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateVolume"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringLike": {
                                "aws:RequestTag/CSIVolumeName": "*"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateVolume"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringLike": {
                                "aws:RequestTag/kubernetes.io/cluster/*": "owned"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DeleteVolume"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringLike": {
                                "ec2:ResourceTag/ebs.csi.aws.com/cluster": "true"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DeleteVolume"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringLike": {
                                "ec2:ResourceTag/CSIVolumeName": "*"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DeleteVolume"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringLike": {
                                "ec2:ResourceTag/kubernetes.io/cluster/*": "owned"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DeleteSnapshot"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringLike": {
                                "ec2:ResourceTag/CSIVolumeSnapshotName": "*"
                            }
                        }
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DeleteSnapshot"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "StringLike": {
                                "ec2:ResourceTag/ebs.csi.aws.com/cluster": "true"
                            }
                        }
                    }
                ]
            }

            # Attach the necessary permissions
            awsebscsidriver_policy = iam.Policy(
                self, "awsebscsidriverpolicy",
                document=iam.PolicyDocument.from_json(
                    awsebscsidriver_policy_document_json)
            )
            awsebscsidriver_service_account.role.attach_inline_policy(
                awsebscsidriver_policy)

            # Install the AWS EBS CSI Driver
            # For more info see https://github.com/kubernetes-sigs/aws-ebs-csi-driver
            awsebscsi_chart = eks_cluster.add_helm_chart(
                "aws-ebs-csi-driver",
                chart="aws-ebs-csi-driver",
                version="2.2.0",
                release="awsebscsidriver",
                repository="https://kubernetes-sigs.github.io/aws-ebs-csi-driver",
                namespace="kube-system",
                values={
                    "controller": {
                        "region": self.region,
                        "serviceAccount": {
                            "create": False,
                            "name": "awsebscsidriver"
                        }
                    },
                    "node": {
                        "serviceAccount": {
                            "create": False,
                            "name": "awsebscsidriver"
                        }
                    }
                }
            )
            awsebscsi_chart.node.add_dependency(
                awsebscsidriver_service_account)

        # AWS EFS CSI Driver
        if (self.node.try_get_context("deploy_aws_efs_csi") == "True"):
            awsefscsidriver_service_account = eks_cluster.add_service_account(
                "awsefscsidriver",
                name="awsefscsidriver",
                namespace="kube-system"
            )

            # Create the PolicyStatements to attach to the role
            awsefscsidriver_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "elasticfilesystem:DescribeAccessPoints",
                    "elasticfilesystem:DescribeFileSystems"
                ],
                "Resource": "*"
            }
            awsefscsidriver_policy_statement_json_2 = {
                "Effect": "Allow",
                "Action": [
                    "elasticfilesystem:CreateAccessPoint"
                ],
                "Resource": "*",
                "Condition": {
                    "StringLike": {
                        "aws:RequestTag/efs.csi.aws.com/cluster": "true"
                    }
                }
            }
            awsefscsidriver_policy_statement_json_3 = {
                "Effect": "Allow",
                "Action": "elasticfilesystem:DeleteAccessPoint",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:ResourceTag/efs.csi.aws.com/cluster": "true"
                    }
                }
            }

            # Attach the necessary permissions
            awsefscsidriver_service_account.add_to_policy(
                iam.PolicyStatement.from_json(awsefscsidriver_policy_statement_json_1))
            awsefscsidriver_service_account.add_to_policy(
                iam.PolicyStatement.from_json(awsefscsidriver_policy_statement_json_2))
            awsefscsidriver_service_account.add_to_policy(
                iam.PolicyStatement.from_json(awsefscsidriver_policy_statement_json_3))

            # Install the AWS EFS CSI Driver
            # For more info see https://github.com/kubernetes-sigs/aws-efs-csi-driver
            awsefscsi_chart = eks_cluster.add_helm_chart(
                "aws-efs-csi-driver",
                chart="aws-efs-csi-driver",
                version="2.2.0",
                release="awsefscsidriver",
                repository="https://kubernetes-sigs.github.io/aws-efs-csi-driver/",
                namespace="kube-system",
                values={
                    "controller": {
                        "serviceAccount": {
                            "create": False,
                            "name": "awsefscsidriver"
                        }
                    },
                    "node": {
                        "serviceAccount": {
                            "create": False,
                            "name": "awsefscsidriver"
                        }
                    }
                }
            )
            awsefscsi_chart.node.add_dependency(
                awsefscsidriver_service_account)

        # Cluster Autoscaler
        if (self.node.try_get_context("deploy_cluster_autoscaler") == "True"):
            clusterautoscaler_service_account = eks_cluster.add_service_account(
                "clusterautoscaler",
                name="clusterautoscaler",
                namespace="kube-system"
            )

            # Create the PolicyStatements to attach to the role
            clusterautoscaler_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "autoscaling:DescribeAutoScalingGroups",
                    "autoscaling:DescribeAutoScalingInstances",
                    "autoscaling:DescribeLaunchConfigurations",
                    "autoscaling:DescribeTags",
                    "autoscaling:SetDesiredCapacity",
                    "autoscaling:TerminateInstanceInAutoScalingGroup"
                ],
                "Resource": "*"
            }

            # Attach the necessary permissions
            clusterautoscaler_service_account.add_to_policy(
                iam.PolicyStatement.from_json(clusterautoscaler_policy_statement_json_1))

            # Install the Cluster Autoscaler
            # For more info see https://github.com/kubernetes/autoscaler
            clusterautoscaler_chart = eks_cluster.add_helm_chart(
                "cluster-autoscaler",
                chart="cluster-autoscaler",
                version="9.10.7",
                release="clusterautoscaler",
                repository="https://kubernetes.github.io/autoscaler",
                namespace="kube-system",
                values={
                    "autoDiscovery": {
                        "clusterName": eks_cluster.cluster_name
                    },
                    "awsRegion": self.region,
                    "rbac": {
                        "serviceAccount": {
                            "create": False,
                            "name": "clusterautoscaler"
                        }
                    },
                    "replicaCount": 2,
                    "extraArgs": {
                        "skip-nodes-with-system-pods": False,
                        "balance-similar-node-groups": True
                    }
                }
            )
            clusterautoscaler_chart.node.add_dependency(
                clusterautoscaler_service_account)

        # Amazon OpenSearch and a fluent-bit to ship our container logs there
        if (self.node.try_get_context("deploy_managed_opensearch") == "True"):
            # Create a new OpenSearch Domain
            # NOTE: I changed this to a removal_policy of DESTROY to help cleanup while I was
            # developing/iterating on the project. If you comment out that line it defaults to keeping
            # the Domain upon deletion of the CloudFormation stack so you won't lose your log data

            os_access_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": "es:*",
                "Principal": {
                    "AWS": "*"
                },
                "Resource": "*"
            }

            # Create SecurityGroup for OpenSearch
            os_security_group = ec2.SecurityGroup(
                self, "OpenSearchSecurityGroup",
                vpc=eks_vpc,
                allow_all_outbound=True
            )
            # Add a rule to allow our new SG to talk to the EKS control plane
            eks_cluster.cluster_security_group.add_ingress_rule(
                os_security_group,
                ec2.Port.all_traffic()
            )
            # Add a rule to allow the EKS control plane to talk to our new SG
            os_security_group.add_ingress_rule(
                eks_cluster.cluster_security_group,
                ec2.Port.all_traffic()
            )

            # The capacity in Nodes and Volume Size/Type for the AWS OpenSearch
            os_capacity = opensearch.CapacityConfig(
                data_nodes=self.node.try_get_context("opensearch_data_nodes"),
                data_node_instance_type=self.node.try_get_context(
                    "opensearch_data_node_instance_type"),
                master_nodes=self.node.try_get_context(
                    "opensearch_master_nodes"),
                master_node_instance_type=self.node.try_get_context(
                    "opensearch_master_node_instance_type")
            )
            os_ebs = opensearch.EbsOptions(
                enabled=True,
                volume_type=ec2.EbsDeviceVolumeType.GP2,
                volume_size=self.node.try_get_context(
                    "opensearch_ebs_volume_size")
            )

            # Note that this AWS OpenSearch domain is optimised for cost rather than availability
            # and defaults to one node in a single availability zone
            os_domain = opensearch.Domain(
                self, "OSDomain",
                removal_policy=core.RemovalPolicy.DESTROY,
                # https://docs.aws.amazon.com/cdk/api/latest/docs/@aws-cdk_aws-opensearchservice.EngineVersion.html
                version=opensearch.EngineVersion.OPENSEARCH_1_0,
                # In EE we'll make this Internet-facing
                # vpc=eks_vpc,
                # vpc_subnets=[ec2.SubnetSelection(
                    subnets=[eks_vpc.private_subnets[0]])],
                # security_groups=[os_security_group],
                capacity= os_capacity,
                ebs= os_ebs,
                access_policies = [iam.PolicyStatement.from_json(
                    os_access_policy_statement_json_1)]
            )

            # Create the Service Account
            fluentbit_service_account=eks_cluster.add_service_account(
                "fluentbit",
                name= "fluentbit",
                namespace= "kube-system"
            )

            fluentbit_policy_statement_json_1={
                "Effect": "Allow",
                "Action": [
                    "es:ESHttp*"
                ],
                "Resource": [
                    os_domain.domain_arn
                ]
            }

            # Add the policies to the service account
            fluentbit_service_account.add_to_policy(
                iam.PolicyStatement.from_json(fluentbit_policy_statement_json_1))
            os_domain.grant_write(fluentbit_service_account)

            # For more info check out https://github.com/fluent/helm-charts/tree/main/charts/fluent-bit
            fluentbit_chart = eks_cluster.add_helm_chart(
                "fluentbit",
                chart="fluent-bit",
                version="0.16.6",
                release="fluent-bit",
                repository="https://fluent.github.io/helm-charts",
                namespace="kube-system",
                values={
                    "serviceAccount": {
                        "create": False,
                        "name": "fluentbit"
                    },
                    "config": {
                        "outputs": "[OUTPUT]\n    Name            es\n    Match           *\n"
                        "    AWS_Region      "+self.region+"\n    AWS_Auth        On\n"
                        "    Host            "+os_domain.domain_endpoint+"\n    Port            443\n"
                        "    TLS             On\n    Replace_Dots    On\n    Logstash_Format    On"
                    }
                }
            )
            fluentbit_chart.node.add_dependency(fluentbit_service_account)

            # Output the OpenSearch Dashboards address in our CloudFormation Stack
            core.CfnOutput(
                self, "OpenSearchDashboardsAddress",
                value="https://" + os_domain.domain_endpoint + "/_dashboards/",
                description="Private endpoint for this EKS environment's OpenSearch to consume the logs",

            )

        # Metrics Server (required for the Horizontal Pod Autoscaler (HPA))
        if (self.node.try_get_context("deploy_metrics_server") == "True"):
            # For more info see https://github.com/bitnami/charts/tree/master/bitnami/metrics-server
            metricsserver_chart = eks_cluster.add_helm_chart(
                "metrics-server",
                chart="metrics-server",
                version="5.10.1",
                release="metricsserver",
                repository="https://charts.bitnami.com/bitnami",
                namespace="kube-system",
                values={
                    "replicas": 2,
                    "apiService": {
                        "create": True
                    }
                }
            )

        # Calico to enforce NetworkPolicies
        if (self.node.try_get_context("deploy_calico_np") == "True"):
            # For more info see https://docs.aws.amazon.com/eks/latest/userguide/calico.html

            # First we need to install the Calico Operator components out of the calico-operator.yaml file
            calico_operator_yaml_file = open("calico-operator.yaml", 'r')
            calico_operator_yaml = list(yaml.load_all(
                calico_operator_yaml_file, Loader=yaml.FullLoader))
            calico_operator_yaml_file.close()
            loop_iteration = 0
            for value in calico_operator_yaml:
                # print(value)
                loop_iteration = loop_iteration + 1
                manifest_id = "CalicoOperator" + str(loop_iteration)
                calico_operator_manifest = eks_cluster.add_manifest(
                    manifest_id, value)

            # Then we need to install the config for the operator out of the calico-crs.yaml file
            calico_crs_yaml_file = open("calico-crs.yaml", 'r')
            calico_crs_yaml = list(yaml.load_all(
                calico_crs_yaml_file, Loader=yaml.FullLoader))
            calico_crs_yaml_file.close()
            calico_crs_manifest = eks_cluster.add_manifest(
                "CalicoCRS", calico_crs_yaml.pop(0))
            calico_crs_manifest.node.add_dependency(calico_operator_manifest)

        # SSM Agent
        if (self.node.try_get_context("deploy_ssm_agent") == "True"):
            # For more information see https://github.com/aws-samples/ssm-agent-daemonset-installer
            # Import ssm-agent.yaml to a list of dictionaries and submit them as a manifest to EKS
            # Read the YAML file
            ssm_agent_yaml_file = open("ssm-agent.yaml", 'r')
            ssm_agent_yaml = list(yaml.load_all(
                ssm_agent_yaml_file, Loader=yaml.FullLoader))
            ssm_agent_yaml_file.close()
            loop_iteration = 0
            for value in ssm_agent_yaml:
                # print(value)
                loop_iteration = loop_iteration + 1
                manifest_id = "SSMAgent" + str(loop_iteration)
                eks_cluster.add_manifest(manifest_id, value)

        # Bastion Instance
        if (self.node.try_get_context("deploy_bastion") == "True"):
            # Create an Instance Profile for our Admin Role to assume w/EC2
            cluster_admin_role_instance_profile = iam.CfnInstanceProfile(
                self, "ClusterAdminRoleInstanceProfile",
                roles=[cluster_admin_role.role_name]
            )

            # Another way into our Bastion is via Systems Manager Session Manager
            if (self.node.try_get_context("create_new_cluster_admin_role") == "True"):
                cluster_admin_role.add_managed_policy(
                    iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

            # Create Bastion
            # Get Latest Amazon Linux AMI
            amzn_linux = ec2.MachineImage.latest_amazon_linux(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                edition=ec2.AmazonLinuxEdition.STANDARD,
                virtualization=ec2.AmazonLinuxVirt.HVM,
                storage=ec2.AmazonLinuxStorage.GENERAL_PURPOSE
            )

            # Create SecurityGroup for bastion
            bastion_security_group = ec2.SecurityGroup(
                self, "BastionSecurityGroup",
                vpc=eks_vpc,
                allow_all_outbound=True
            )

            # Add a rule to allow our new SG to talk to the EKS control plane
            eks_cluster.cluster_security_group.add_ingress_rule(
                bastion_security_group,
                ec2.Port.all_traffic()
            )

            # Create our EC2 instance for bastion
            bastion_instance = ec2.Instance(
                self, "BastionInstance",
                instance_type=ec2.InstanceType(
                    self.node.try_get_context("bastion_node_type")),
                machine_image=amzn_linux,
                role=cluster_admin_role,
                vpc=eks_vpc,
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PUBLIC),
                security_group=bastion_security_group,
                block_devices=[ec2.BlockDevice(
                    device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(self.node.try_get_context("bastion_disk_size")))]
            )

            # Set up our kubectl and fluxctl
            bastion_instance.user_data.add_commands(
                "curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.21.2/2021-07-05/bin/linux/amd64/kubectl")
            bastion_instance.user_data.add_commands("chmod +x ./kubectl")
            bastion_instance.user_data.add_commands("mv ./kubectl /usr/bin")
            bastion_instance.user_data.add_commands(
                "curl -s https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash -")
            bastion_instance.user_data.add_commands(
                "curl -s https://fluxcd.io/install.sh | bash -")
            bastion_instance.user_data.add_commands(
                "curl --silent --location https://rpm.nodesource.com/setup_14.x | bash -")
            bastion_instance.user_data.add_commands(
                "yum install nodejs git -y")
            bastion_instance.user_data.add_commands(
                "su -c \"aws eks update-kubeconfig --name " + eks_cluster.cluster_name + " --region " + self.region + "\" ssm-user")

            # Wait to deploy Bastion until cluster is up and we're deploying manifests/charts to it
            # This could be any of the charts/manifests I just picked this one as almost everybody will want it
            bastion_instance.node.add_dependency(metricsserver_chart)

        # Client VPN
        if (self.node.try_get_context("deploy_client_vpn") == "True"):
            # Create and upload your client and server certs as per https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html#mutual
            # And then put the ARNs for them into the items below
            client_cert = cm.Certificate.from_certificate_arn(
                self, "ClientCert",
                certificate_arn=self.node.try_get_context("vpn_client_certificate_arn"))
            server_cert = cm.Certificate.from_certificate_arn(
                self, "ServerCert",
                certificate_arn=self.node.try_get_context("vpn_server_certificate_arn"))

            # Create SecurityGroup for VPN
            vpn_security_group = ec2.SecurityGroup(
                self, "VPNSecurityGroup",
                vpc=eks_vpc,
                allow_all_outbound=True
            )
            # Add a rule to allow our new SG to talk to the EKS control plane
            eks_cluster.cluster_security_group.add_ingress_rule(
                vpn_security_group,
                ec2.Port.all_traffic()
            )

            if (self.node.try_get_context("deploy_managed_opensearch") == "True"):
                # Add a rule to allow our new SG to talk to Elastic
                os_security_group.add_ingress_rule(
                    vpn_security_group,
                    ec2.Port.all_traffic()
                )

            # Create CloudWatch Log Group and Stream and keep the logs for 1 month
            log_group = logs.LogGroup(
                self, "VPNLogGroup",
                retention=logs.RetentionDays.ONE_MONTH
            )
            log_stream = log_group.add_stream("VPNLogStream")

            endpoint = ec2.CfnClientVpnEndpoint(
                self, "VPNEndpoint",
                description="EKS Client VPN",
                authentication_options=[{
                    "type": "certificate-authentication",
                    "mutualAuthentication": {
                        "clientRootCertificateChainArn": client_cert.certificate_arn
                    }
                }],
                client_cidr_block=self.node.try_get_context(
                    "vpn_client_cidr_block"),
                server_certificate_arn=server_cert.certificate_arn,
                connection_log_options={
                    "enabled": True,
                    "cloudwatchLogGroup": log_group.log_group_name,
                    "cloudwatchLogStream": log_stream.log_stream_name
                },
                split_tunnel=True,
                security_group_ids=[vpn_security_group.security_group_id],
                vpc_id=eks_vpc.vpc_id
            )

            ec2.CfnClientVpnAuthorizationRule(
                self, "ClientVpnAuthRule",
                client_vpn_endpoint_id=endpoint.ref,
                target_network_cidr=eks_vpc.vpc_cidr_block,
                authorize_all_groups=True,
                description="Authorize the Client VPN access to our VPC CIDR"
            )

            ec2.CfnClientVpnTargetNetworkAssociation(
                self, "ClientVpnNetworkAssociation",
                client_vpn_endpoint_id=endpoint.ref,
                subnet_id=eks_vpc.private_subnets[0].subnet_id
            )

        # CloudWatch Container Insights - Metrics
        if (self.node.try_get_context("deploy_cloudwatch_container_insights_metrics") == "True"):
            # For more info see https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-metrics.html

            # Create the Service Account
            cw_container_insights_sa = eks_cluster.add_service_account(
                "cloudwatch-agent",
                name="cloudwatch-agent",
                namespace="kube-system"
            )
            cw_container_insights_sa.role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy"))

            # Set up the settings ConfigMap
            cw_container_insights_configmap = eks_cluster.add_manifest("CWAgentConfigMap",
                                                                       {
                                                                           "apiVersion": "v1",
                                                                           "data": {
                                                                               "cwagentconfig.json": "{\n  \"logs\": {\n    \"metrics_collected\": {\n      \"kubernetes\": {\n        \"cluster_name\": \"" + eks_cluster.cluster_name + "\",\n        \"metrics_collection_interval\": 60\n      }\n    },\n    \"force_flush_interval\": 5\n  }\n}\n"
                                                                           },
                                                                           "kind": "ConfigMap",
                                                                           "metadata": {
                                                                               "name": "cwagentconfig",
                                                                               "namespace": "kube-system"
                                                                           }
                                                                       }
                                                                       )

            # Import cloudwatch-agent.yaml to a list of dictionaries and submit them as a manifest to EKS
            # Read the YAML file
            cw_agent_yaml_file = open("cloudwatch-agent.yaml", 'r')
            cw_agent_yaml = list(yaml.load_all(
                cw_agent_yaml_file, Loader=yaml.FullLoader))
            cw_agent_yaml_file.close()
            loop_iteration = 0
            for value in cw_agent_yaml:
                # print(value)
                loop_iteration = loop_iteration + 1
                manifest_id = "CWAgent" + str(loop_iteration)
                eks_cluster.add_manifest(manifest_id, value)

        # CloudWatch Container Insights - Logs
        if (self.node.try_get_context("deploy_cloudwatch_container_insights_logs") == "True"):
            # Create the Service Account
            cwlogs_service_account = eks_cluster.add_service_account(
                "aws-for-fluent-bit-service-account",
                name="aws-for-fluent-bit",
                namespace="kube-system"
            )

            cwlogs_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                    "logs:DescribeLogGroups",
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutRetentionPolicy"
                ],
                "Resource": ["*"]
            }

            # Add the policies to the service account
            cwlogs_service_account.add_to_policy(
                iam.PolicyStatement.from_json(cwlogs_policy_statement_json_1))

            # For more info check out https://github.com/aws/eks-charts/tree/master/stable/aws-for-fluent-bit
            fluentbit_chart_cwlogs = eks_cluster.add_helm_chart(
                "aws-for-fluent-bit",
                chart="aws-for-fluent-bit",
                version="0.1.11",
                release="aws-for-fluent-bit",
                repository="https://aws.github.io/eks-charts",
                namespace="kube-system",
                values={
                    "serviceAccount": {
                        "create": False,
                        "name": "aws-for-fluent-bit"
                    },
                    "cloudWatch": {
                        "region": self.region,
                        "logRetentionDays": self.node.try_get_context("cloudwatch_container_insights_logs_retention_days")
                    },
                    "firehose": {
                        "enabled": False
                    },
                    "kinesis": {
                        "enabled": False
                    },
                    "elasticsearch": {
                        "enabled": False
                    }
                }
            )
            fluentbit_chart_cwlogs.node.add_dependency(cwlogs_service_account)

        # Security Group for Pods
        if (self.node.try_get_context("deploy_sg_for_pods") == "True"):
            # The EKS Cluster was still defaulting to 1.7.5 on 12/9/21 and SG for Pods requires 1.7.7
            # Upgrading that to the latest version 1.9.0 via the Helm Chart
            # If this process somehow breaks the CNI you can repair it manually by following the steps here:
            # https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html#updating-vpc-cni-add-on
            # TODO: Move this to the CNI Managed Add-on when that supports flipping the required ENABLE_POD_ENI setting

            # Adopting the existing aws-node resources to Helm
            patch_types = ["DaemonSet", "ClusterRole", "ClusterRoleBinding"]
            patches = []
            for kind in patch_types:
                patch = eks.KubernetesPatch(
                    self, "CNI-Patch-"+kind,
                    cluster=eks_cluster,
                    resource_name=kind + "/aws-node",
                    resource_namespace="kube-system",
                    apply_patch={
                        "metadata": {
                            "annotations": {
                                "meta.helm.sh/release-name": "aws-vpc-cni",
                                "meta.helm.sh/release-namespace": "kube-system",
                            },
                            "labels": {
                                "app.kubernetes.io/managed-by": "Helm"
                            }
                        }
                    },
                    restore_patch={},
                    patch_type=eks.PatchType.STRATEGIC
                )
                patches.append(patch)

            # Create the Service Account
            sg_pods_service_account = eks_cluster.add_service_account(
                "aws-node",
                name="aws-node-helm",
                namespace="kube-system"
            )

            # Give it the required policies
            sg_pods_service_account.role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKS_CNI_Policy"))
            # sg_pods_service_account.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSVPCResourceController"))
            eks_cluster.role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSVPCResourceController"))

            # Deploy the Helm chart
            # For more info check out https://github.com/aws/eks-charts/tree/master/stable/aws-vpc-cni
            # Note that for some regions different account # required - https://docs.aws.amazon.com/eks/latest/userguide/add-ons-images.html
            sg_pods_chart = eks_cluster.add_helm_chart(
                "aws-vpc-cni",
                chart="aws-vpc-cni",
                version="1.1.9",
                release="aws-vpc-cni",
                repository="https://aws.github.io/eks-charts",
                namespace="kube-system",
                values={
                    "init": {
                        "image": {
                            "region": self.region,
                            "account": "602401143452",
                        },
                        "env": {
                            "DISABLE_TCP_EARLY_DEMUX": True
                        }
                    },
                    "image": {
                        "region": self.region,
                        "account": "602401143452"
                    },
                    "env": {
                        "ENABLE_POD_ENI": True
                    },
                    "serviceAccount": {
                        "create": False,
                        "name": "aws-node-helm"
                    },
                    "crd": {
                        "create": False
                    },
                    "originalMatchLabels": True
                }
            )
            # This depends both on the service account and the patches to the existing CNI resources having been done first
            sg_pods_chart.node.add_dependency(cwlogs_service_account)
            for patch in patches:
                sg_pods_chart.node.add_dependency(patch)

        # Secrets Manager CSI Driver
        if (self.node.try_get_context("deploy_secretsmanager_csi") == "True"):
            # For more information see https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_csi_driver.html

            # First we install the Secrets Store CSI Driver Helm Chart
            # For mor information see https://github.com/kubernetes-sigs/secrets-store-csi-driver/tree/main/charts/secrets-store-csi-driver
            csi_secrets_store_chart = eks_cluster.add_helm_chart(
                "csi-secrets-store",
                chart="secrets-store-csi-driver",
                version="0.3.0",
                release="csi-secrets-store",
                repository="https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts",
                namespace="kube-system",
                # Since sometimes you want these secrets as environment variables enabling syncSecret
                # For more info see https://secrets-store-csi-driver.sigs.k8s.io/topics/sync-as-kubernetes-secret.html
                values={
                    "syncSecret": {
                        "enabled": True
                    }
                }
            )

            # Install the AWS Provider
            # See https://github.com/aws/secrets-store-csi-driver-provider-aws for more info

            # Create the IRSA Mapping
            secrets_csi_sa = eks_cluster.add_service_account(
                "secrets-csi-sa",
                name="csi-secrets-store-provider-aws",
                namespace="kube-system"
            )

            # Associate the IAM Policy
            # NOTE: you really want to specify the secret ARN rather than * in the Resource
            # Consider namespacing these by cluster/environment name or some such as in this example:
            # "Resource": ["arn:aws:secretsmanager:Region:AccountId:secret:TestEnv/*"]
            secrets_csi_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                "Resource": ["*"]
            }
            secrets_csi_sa.add_to_policy(iam.PolicyStatement.from_json(
                secrets_csi_policy_statement_json_1))

            # Deploy the manifests from secrets-store-csi-driver-provider-aws.yaml
            secrets_csi_provider_yaml_file = open(
                "secrets-store-csi-driver-provider-aws.yaml", 'r')
            secrets_csi_provider_yaml = list(yaml.load_all(
                secrets_csi_provider_yaml_file, Loader=yaml.FullLoader))
            secrets_csi_provider_yaml_file.close()
            loop_iteration = 0
            for value in secrets_csi_provider_yaml:
                # print(value)
                loop_iteration = loop_iteration + 1
                manifest_id = "SecretsCSIProviderManifest" + \
                    str(loop_iteration)
                manifest = eks_cluster.add_manifest(manifest_id, value)
                manifest.node.add_dependency(secrets_csi_sa)

        # Kubernetes External Secrets
        if (self.node.try_get_context("deploy_external_secrets") == "True"):
            # For more information see https://github.com/external-secrets/kubernetes-external-secrets
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
            externalsecrets_service_account.add_to_policy(
                iam.PolicyStatement.from_json(externalsecrets_policy_statement_json_1))

            # Deploy the Helm Chart
            external_secrets_chart = eks_cluster.add_helm_chart(
                "external-secrets",
                chart="kubernetes-external-secrets",
                version="8.3.0",
                repository="https://external-secrets.github.io/kubernetes-external-secrets/",
                namespace="kube-system",
                release="external-secrets",
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

        # Kubecost
        if (self.node.try_get_context("deploy_kubecost") == "True"):
            # For more information see https://www.kubecost.com/install#show-instructions
            # And https://github.com/kubecost/cost-analyzer-helm-chart/tree/master

            # If we're deploying Prometheus then we don't need the node exporter
            if (self.node.try_get_context("deploy_amp") == "True"):
                kubecost_values = {
                    "kubecostToken": self.node.try_get_context("kubecost_token"),
                    "prometheus": {
                        "nodeExporter": {
                            "enabled": False
                        },
                        "serviceAccounts": {
                            "nodeExporter": {
                                "create": False
                            }
                        }
                    }
                }
            else:
                kubecost_values = {
                    "kubecostToken": self.node.try_get_context("kubecost_token")}

            # Deploy the Helm Chart
            kubecost_chart = eks_cluster.add_helm_chart(
                "kubecost",
                chart="cost-analyzer",
                version="1.87.0",
                repository="https://kubecost.github.io/cost-analyzer/",
                namespace="kube-system",
                release="kubecost",
                values=kubecost_values
            )

            # Deploy an internal NLB
            # In EE flipping this to Internet-facing 
            kubecostnlb_manifest = eks_cluster.add_manifest("KubecostNLB", {
                "kind": "Service",
                "apiVersion": "v1",
                "metadata": {
                    "name": "kubecost-nlb",
                    "namespace": "kube-system",
                    "annotations": {
                        "service.beta.kubernetes.io/aws-load-balancer-type": "nlb-ip",
                        "service.beta.kubernetes.io/aws-load-balancer-internal": "false"
                    }
                },
                "spec": {
                    "ports": [
                        {
                            "name": "service",
                            "protocol": "TCP",
                            "port": 80,
                            "targetPort": 9090
                        }
                    ],
                    "selector": {
                        "app.kubernetes.io/name": "cost-analyzer"
                    },
                    "type": "LoadBalancer"
                }
            })
            kubecostnlb_manifest.node.add_dependency(kubecost_chart)

        # Amazon Managed Prometheus (AMP)
        if (self.node.try_get_context("deploy_amp") == "True"):
            # For more information see https://aws.amazon.com/blogs/mt/getting-started-amazon-managed-service-for-prometheus/

            # Use our AMPCustomResource to provision/deprovision the AMP
            # TODO remove this and use the proper CDK construct when it becomes available
            amp_workspace_id = AMPCustomResource(
                self, "AMPCustomResource").workspace_id
            # Output the AMP Workspace ID and Export it
            core.CfnOutput(
                self, "AMPWorkspaceID",
                value=amp_workspace_id,
                description="The ID of the AMP Workspace",
                export_name="AMPWorkspaceID"
            )

            # Create IRSA mapping
            amp_sa = eks_cluster.add_service_account(
                "amp-sa",
                name="amp-iamproxy-service-account",
                namespace="kube-system"
            )

            # Associate the IAM Policy
            amp_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "aps:RemoteWrite",
                    "aps:QueryMetrics",
                    "aps:GetSeries",
                    "aps:GetLabels",
                    "aps:GetMetricMetadata"
                ],
                "Resource": ["*"]
            }
            amp_sa.add_to_policy(iam.PolicyStatement.from_json(
                amp_policy_statement_json_1))

            # Install Prometheus with a low 1 hour local retention to ship the metrics to the AMP
            # For more information see https://github.com/prometheus-community/helm-charts/tree/main/charts/prometheus
            amp_prometheus_chart = eks_cluster.add_helm_chart(
                "prometeus-chart",
                chart="prometheus",
                version="14.8.0",
                release="prometheus-for-amp",
                repository="https://prometheus-community.github.io/helm-charts",
                namespace="kube-system",
                values={
                    "serviceAccounts": {
                        "server": {
                            "annotations": {
                                "eks.amazonaws.com/role-arn": amp_sa.role.role_arn,
                            },
                            "name": "amp-iamproxy-service-account",
                            "create": False
                        },
                        "alertmanager": {
                            "create": False
                        },
                        "pushgateway": {
                            "create": False
                        }
                    },
                    "server": {
                        "remoteWrite": [{
                            "queue_config": {
                                "max_samples_per_send": 1000,
                                "max_shards": 200,
                                "capacity": 2500
                            },
                            "url": "https://aps-workspaces."+self.region+".amazonaws.com/workspaces/"+amp_workspace_id+"/api/v1/remote_write",
                            "sigv4": {
                                "region": self.region
                            }
                        }],
                        "statefulSet": {
                            "enabled": True
                        },
                        "retention": "1h"
                    },
                    "alertmanger": {
                        "enabled": False
                    },
                    "pushgateway": {
                        "enabled": False
                    }
                }
            )
            amp_prometheus_chart.node.add_dependency(amp_sa)

        # Self-Managed Grafana for AMP
        if (self.node.try_get_context("deploy_grafana_for_amp") == "True"):
            # Install a self-managed Grafana to visualise the AMP metrics
            # NOTE You likely want to use the AWS Managed Grafana (AMG) in production
            # We are using this as AMG requires SSO/SAML and is harder to include in the template
            # For more information see https://github.com/grafana/helm-charts/tree/main/charts/grafana
            amp_grafana_chart = eks_cluster.add_helm_chart(
                "amp-grafana-chart",
                chart="grafana",
                version="6.16.0",
                release="grafana-for-amp",
                repository="https://grafana.github.io/helm-charts",
                namespace="kube-system",
                values={
                    "serviceAccount": {
                        "name": "amp-iamproxy-service-account",
                        "annotations": {
                            "eks.amazonaws.com/role-arn": amp_sa.role.role_arn
                        },
                        "create": False
                    },
                    "grafana.ini": {
                        "auth": {
                            "sigv4_auth_enabled": True
                        }
                    }
                }
            )
            amp_grafana_chart.node.add_dependency(amp_prometheus_chart)

            # Deploy an internal NLB to Grafana
            amp_grafananlb_manifest = eks_cluster.add_manifest("AMPGrafanaNLB", {
                "kind": "Service",
                "apiVersion": "v1",
                "metadata": {
                    "name": "amp-grafana-nlb",
                    "namespace": "kube-system",
                    "annotations": {
                        "service.beta.kubernetes.io/aws-load-balancer-type": "nlb-ip",
                        "service.beta.kubernetes.io/aws-load-balancer-internal": "true"
                    }
                },
                "spec": {
                    "ports": [
                        {
                            "name": "service",
                            "protocol": "TCP",
                            "port": 80,
                            "targetPort": 3000
                        }
                    ],
                    "selector": {
                        "app.kubernetes.io/name": "grafana"
                    },
                    "type": "LoadBalancer"
                }
            })
            amp_grafananlb_manifest.node.add_dependency(amp_grafana_chart)


app = core.App()
if app.node.try_get_context("account").strip() != "":
    account = app.node.try_get_context("account")
else:
    account = os.environ.get("CDK_DEPLOY_ACCOUNT",
                             os.environ["CDK_DEFAULT_ACCOUNT"])

if app.node.try_get_context("region").strip() != "":
    region = app.node.try_get_context("region")
else:
    region = os.environ.get("CDK_DEPLOY_REGION",
                            os.environ["CDK_DEFAULT_REGION"])
# Note that if we didn't pass through the ACCOUNT and REGION from these environment variables that
# it won't let us create 3 AZs and will only create a max of 2 - even when we ask for 3 in eks_vpc
eks_cluster_stack = EKSClusterStack(
    app, "EKSClusterStack", env=core.Environment(account=account, region=region))
app.synth()
