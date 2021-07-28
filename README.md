# EKS Quick Start (CDK - Python) Workshop

This workshop is explaining how to use the new [AWS Quick Start for EKS based on CDK in Python](https://github.com/aws-quickstart/quickstart-eks-cdk-python) to build out an example EKS environment.

It will also touch on how to use CDK as a tool to manage your workloads on top of Kubernetes in addition to provisioning the cluster together with the required infrastructure add-ons.

## Explore the CDK environment that has already been deployed into the account for you

In the interests of time, we have already deployed the EKS Quick Start into this account for you. This process takes a little under 30 minutes end-to-end. You can see the template which deployed it in the file `ee/cluster-bootstrap/eks_cluster.py`. Note that some of the parameters that the template references are stored in `ee/cluster-bootstrap/cdk.json`.

If you want to see how long it actually took, it was actually deployed via AWS CodeBuild (which ran the `cdk deploy` command for us) as the last step of setting up your account in Event Engine. To check that out:
1. Go the AWS Console
1. Go to the CodeBuild Service
1. Go to build history on the left-hand navigation bar
1. Note the time under `Duration`
1. To see the logs of the process click on the link under `Build run`
1. Scroll down to see the CDK log output of the process

Leveraging AWS CodeBuild or another such tool to provision and manage environments with this template via GitOps practices like this - instead of doing it by hand from a Bastion or somebody's laptop especially - has many benefits.

### Exploring our CDK template(s) and CDK's benefits here

The two CDK templates we'll be using today are `ee/cluster-bootstrap/eks_cluster.py` and `ghost_example/ghost_example.py`.

A few noteworthy things that make the CDK a great tool for provisioning these EKS environments:

* CDK makes setting up [IAM Role to Service Account (IRSA) mappings](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) easy. And since much of the Add-ons we're setting up with the cluster are to integrate it better with AWS, and thus require AWS API access, this is important.

  ```
  # Create the Kubernetes Service Account and corresponding IAM Role
  awsebscsidriver_service_account = eks_cluster.add_service_account(
    "awsebscsidriver",
    name="awsebscsidriver",
    namespace="kube-system"
  )

  # Create the PolicyStatements to attach to the IAM role
  awsebscsidriver_policy_statement_json_1 = {
      "Effect": "Allow",
      "Action": [
          "ec2:AttachVolume",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteSnapshot",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInstances",
          "ec2:DescribeSnapshots",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DescribeVolumesModifications",
          "ec2:DetachVolume",
          "ec2:ModifyVolume"
      ],
      "Resource": "*"
  }

  # Attach our PolicyStatement to the IAM Role
  awsebscsidriver_service_account.add_to_policy(iam.PolicyStatement.from_json(awsebscsidriver_policy_statement_json_1))
  ```

* CDK extends Cloudformation to be able to deploy [Kubernetes manifests](https://docs.aws.amazon.com/cdk/api/latest/docs/@aws-cdk_aws-eks.Cluster.html#addwbrmanifestid-manifest) (though converted to JSON) as well as [Helm Charts](https://docs.aws.amazon.com/cdk/api/latest/docs/@aws-cdk_aws-eks.Cluster.html#addwbrhelmwbrchartid-options).

  ```
  # Deploy an internal NLB in to Grafana
  grafananlb_manifest = eks_cluster.add_manifest("GrafanaNLB",{
    "kind": "Service",
    "apiVersion": "v1",
    "metadata": {
      "name": "grafana-nlb",
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
        "targetPort": 3000
      }
      ],
      "selector": {
        "app.kubernetes.io/name": "grafana"
      },
      "type": "LoadBalancer"
    }
  })
  ```

  ```
  # Install the metrics-server (required for the HPA)
  metricsserver_chart = eks_cluster.add_helm_chart(
      "metrics-server",
      chart="metrics-server",
      version="5.9.1",
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
  ```
* Finally, CDK supports dynamic references back and forth even between AWS things and Kubernetes things. Here we're able to say "please fill in this Kubernetes Manifest with the name of a secret that will be randomly generated when the CDK makes the RDS database in question. This also means it knows the RDS needs to be created *before* the manifest:

```
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
```

### Have a look through the EKS console at our cluster and workloads

1. Go to the EKS Service in the AWS Console (use the search box at the top of the page)
1. Click on `Clusters` under EKS in the navigation pane on the left side
1. Click the name of the only Cluster on the list
1. In the `Overview` Tab you'll see the Nodes
1. In the `Workloads` Tab you'll see the Deployments, ReplicaSets and StatefulSets
1. If you click on one of the workloads you'll see more details including links to the Pods
1. If you click on one of the Pods you'll see various details about that Pod
1. If you click back to the main Cluster page (you can click on the cluster name at the top navigation breadcrumb) then click to the `Configuration` Tab
1. The `Compute` tab is where you can configure Managed Node Groups and Fargate Profiles
1. If you click into the only `Node group` on the list you'll see more details as well as various configuration options for our managed pool of EC2 Instances that serve as our Kubernetes worker Nodes.
1. First click back to the main Cluster page (you can click on the cluster name at the navigation breadcrumb) then into the `Networking` tab which will show you the VPC and subnets the cluster was configured with
1. The `Add-ons` tab is where our future work with Managed Add-ons will be exposed
1. The `Logging` tab will show you if the various control plane logging options are enabled (our Quick Start does enable them)
1. The `Update History` tab will show you an audit trail of various upgrades and changes made to the cluster since it was created

### Use SSM Session Manager to connect to our Bastion/Jumpbox and run kubectl

1. Go to the EC2 Service in the AWS Console
1. Click on `Instances` on the left hand navigation pane
1. Put a tick next to the Instance named `EKSClusterStack/BastionInstance
1. Click the `Connect` button above the list
1. Go to the `Session Manager` tab and click the `Connect` button
1. Run `sudo bash` to become root (as we installed various things via UserData which runs as root)
1. Run `kubectl get nodes -o wide` to see the Instances our Managed Node Group has provisioned for our cluster (-o changes the output format and wide tells it to show us some more detail)
1. Run `kubectl get pods -A` to see all the Pods currently running on our cluster in all Namespaces (-A is the equivalent to --all-namespaces)
    1. This gives you a sense of all the add-ons that the Quick Start has set up on our cluster for us. If this was a new EKS cluster without the Quick Start you'd only see three things (kube-proxy, coredns and aws-node (our CNI)). 
    1. Also note all the Add-ons we've deployed we've put in the kube-system namespace so you'll need to specify that if you want to interact with these

NOTE: The authentication to the cluster was based on the IAM Role assigned to our Bastion Instance being set up by the Quick Start with the necessary access to the Cluster. This IAM role assignment functionality automatically provides and rotates AWS Access Keys and Secrets to our Bastion that are leveraged by our ~/.kube/config and kubectl to 'just work'. You can do similar things with AWS CodeBuild or Lambda or any other AWS service where you can assign an AWS IAM Role.

## Install Ghost via another loosely coupled CDK Stack

We'll kick off the Ghost CDK deployment (which will take awhile creating the MySQL RDS database etc.) and then while that is deploying we'll have a look at the CDK template to see what it is doing for us.

1. If you are not still in the SSM Session to the Bastion as in the previous section re-open that
1. If your terminal says sh-4.2$ instead of root@... then run a `sudo bash` command to become root
1. Run:
    1. `cd ~`
    1. `git clone https://github.com/jasonumiker/eks-quickstart-immersion.git`
    1. `cd eks-quickstart-immersion/ghost_example/`
    1. `npm install -g aws-cdk` to install the CDK
    1. `pip3 install -r requirements.txt` to install the Python CDK bits
    1. `cdk synth` to generate the CloudFormation from the `ghost_example.py` CDK template and make sure everything is working. It will not only output it to the screen but also store it in the `cdk.out/` folder
    1. `cdk deploy` to deploy template this to our account in a new CloudFormation stack
    1. Answer `y` to the confirmation and press Enter/Return

### Understanding what is actually happening while we wait for it to complete

When we run our `ghost_example.py` CDK template there are both AWS and Kubernetes components that CDK provisions for us.
![Git Flow Diagram](diagram1.PNG?raw=true "Git Flow Diagram")

We are also adding a new controller/operator to Kubernetes - [kubernetes-external-secrets](https://github.com/external-secrets/kubernetes-external-secrets) - which is UPSERTing the AWS Secrets Manager secret that CDK is creating into Kubernetes so that we can easily consume this in our Pod(s). This joins the existing [AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.2/) which turns our Ingress Specs into an integration/delegation to the AWS Application Load Balancer (ALB).
![Operator Flow Diagram](diagram2.PNG?raw=true "Operator Flow Diagram")

### Cross-Stack CDK

We're deploying Ghost in a totally seperate CDK stack in a seperate file. This is made possible by a few things:
1. Some CDK Constructs like VPC can import object, with all the associated properties and methods, from existing environments. In the case of VPC you'll see this is all it takes to import our existing VPC we want to deploy into by its name:
```
vpc = ec2.Vpc.from_lookup(self, 'VPC', vpc_name="EKSClusterStack/VPC")
```
1. Other Constructs like EKS we need to tell it several of the parameters for it to reconstruct the object. Here we need to tell it a few things like the `open_id_connect_provider`, the `kubectl_role_arn`, etc. for it to give us an object we can call/use like we'd created the EKS cluster in *this* template. 

We pass these parameters across our Stacks using CloudFormation Exports (Outputs in one CF stack we can reference in another):
```
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
```
![CF Exports](diagram3.PNG?raw=true "CF Exports")

### Once the deployment finishes we'll explore what now exists and connect to Ghost

1. Run `kubectl get ingresses` to see the address for the ALB in front of our service
1. Go to that address in your web browser to see the service
1. Go to that address with the path `/ghost` appended to the end to get to the management interface. Set up an initial account there (before some random person on the Internet does it for you!)
1. Go to the EC2 Service in the AWS Console
1. Go to `Load Balancers` on the left hand navigation pane
1. Select the `k8s-default-ghost-...` Load Balancer - this is the ALB that the AWS Ingress Controller created for us
1. Select the Monitoring Tab to see some metrics about the traffic flowing though to our new Ghost
1. Select `Target Groups` on the left-hand navigation pane
1. Select the `k8s-default-ghost-...` Target Group
1. Select the Targets tab on the lower pane
1. The AWS Load Balancer controller adds/removes the Pod IPs directly as LB Targets as they come and go
1. Go to the Secrets Manager service in the AWS Console
1. Click on the Secret named `RDSSecret...`
1. Scroll down until you see the `Secret value` section and click the `Retrieve secret value` button. This secret was created by the CDK as part of its creation of the MySQL RDS. We map this secret into a Kubernetes secret our app consumes to know how to connect to the database with the [kubernetes-external-secrets](https://github.com/external-secrets/kubernetes-external-secrets) add-on we install in this stack. That in turn is passed in at runtime by Kubernetes as environment variables.

## Check out the included observability components (Prometheus/Grafana and AWS Elasticsearch/Kibana)

### Self-managed Prometheus and Grafana

Since the AWS Managed Prometheus and Grafana are not yet available in Sydney, we're going to deploy the [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) for running them on the cluster for now. We'll revisit this when we can get the AWS managed offering (like we have with the AWS Managed Elasticsearch below) locally.

In order to connect to the Grafana we have provisioned an AWS Network Load Balancer (NLB) in front of it as part of the Quick Start. In the main Quick Start this is provisioned into a *private* subnet in the VPC where you need a VPN (either Client or Site-to-Site) or a DirectConnect to reach it. For the purposes of this lab we changed it to be exposed to the Internet.

To connect to it:
1. If you are not still in the SSM Session to the Bastion as in the previous section re-open that
1. If your terminal says sh-4.2$ instead of root@... then run a `sudo bash` command to become root
1. Run `kubectl get service grafana-nlb --namespace=kube-system`
1. The EXTERNAL-IP listed there is the address of the public load balancer - copy and paste that into your browser
1. You'll see a login screen - the username is admin and the password is prom-operator

There are some default dashboards that ship with this which you can see by going to Home on top. This will take you to a list view of the available dashboards. Some good ones to check out include:
* `Kubernetes / Compute Resources / Cluster` - This gives you a whole cluster view
* `Kubernetes / Compute Resources / Namespace (Pods)` - There is a namespace dropdown at the top and it'll show you the graphs including the consumption in that namespace broken down by Pod
* `Kubernetes / Compute Resources / Namespace (Workloads)` - Similar to the Pod view but instead focuses on Deployment, StatefulSet and DaemonSet views

Within all of these dashboards you can click on names as links and it'll drill down to show you details relevant to that item.

### AWS Managed Elasticsearch and Kibana

We have also configured a fluent-bit DaemonSet to ship all our container logs to an AWS Managed Elasticsearch. You search/visualise/filter these in the Kibana UI.

In the main Quick Start this is provisioned into a *private* subnet in the VPC where you need a VPN (either Client or Site-to-Site) or a DirectConnect to reach it. For the purposes of this lab we changed it to be exposed to the Internet.

Since there is no login/password associated with Kibana in our setup, we are going to only allow your IP address to connect rather than the whole Internet. Note that for production use we would encourage you to set up SAML or Cognito for authentication as described here - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/saml.html and https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html.

First go to https://www.whatismyip.com/ and note your IP address

To allow our IP address access to Kibana:
1. Go to the Elasticsearch service in the AWS Console
1. Click on the name of the one Elasticsearch Domain that you see (it is a link)
1. Click on the `Actions` button on the top and choose `Modify access policy`
1. Put a comma after the bracket of the first statement and add a 2nd statement as follows - replacing 1.1.1.1 with your IP from https://www.whatismyip.com:
```
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "*"
  },
  "Action": [
    "es:*"
  ],
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": [
        "1.1.1.1"
      ]
    }
  },
  "Resource": "*"
}
```

Then to connect to Kibana and see what we can do there:
1. If you are not already there go to the Elasticsearch service in the AWS Console and click on the link that is the name of the Domain
1. Click on the link next to `Kibana`
1. Click "Explore on my own" in the Welcome page
1. Click "Connect to your Elasticsearch index" under "Use Elasticsearch Data"
1. Close the About index patterns box
1. Click the Create Index Pattern button
1. In the Index pattern name box enter `fluent-bit` and click Next step
1. Pick `@timestamp` from the dropbown box and click Create index pattern
1. Then go back Home and click Discover
1. This is showing you all the logs from all the containers aggregated together. Let's see how to drill down a bit:
    1. The search box uses Kibana Query Language (KQL) - there is a guide to it here - https://www.elastic.co/guide/en/kibana/current/kuery-query.html
    1. If we wanted to only see logs that came from kubernetes Pods with the label app then we could type `kubernetes.labels.app: *` into the Search box and hit Enter/Return
    1. By default it is also showing us things from the last 15 minutes based on the field to the right of the Search box. If we wanted to increase that to anytime today we could click the Calendar button on the left of that and click the `Today` link
    1. Now we are seeing all the logs from Pods with the label app it received Today. To drill down further and only see log lines from the Ghost app we could change our KQL Search to be `kubernetes.labels.app: ghost`
    1. Now we are seeing all our logs from the Ghost Pods. If you click the > on the left hand side of one of those lines you'll see all the fields shipped with the logs. Click on the JSON tab to see the raw JSON that each record is sent to Elasticsearch from fluent-bit - and all the metadata wrapped around that log field you can search or filter on.

Given that you often have many Pods behind each service which come and go being able to aggregate them all together and search/filter/visualise them is an important capability in running your EKS environment(s).

## Demonstrate EBS and EFS PersistentVolumes via the included CSI Driver

### EBS

Elastic Block Storage (EBS) is the AWS block storage service in AWS. We've integrated it with our EKS environment by adding the CSI driver AWS maintains to the cluster as an add-on in the Quick Start.

Let's see an example of how that is used.

1. If you are not still in the SSM Session to the Bastion as in the previous section re-open that
1. If your terminal says sh-4.2$ instead of root@... then run a `sudo bash` command to become root
1. Run:
    1. `cd ~/eks-quickstart-immersion/ebs_example`
    1. `cat ebs-storageclass.yaml` and note how this is creating a StorageClass that will use our EBS CSI Driver as the provisioner
    1. `cat ebs-pod.yaml` and note how we create a PersistentVolumeClaim to say we want a new volume using that EBS StorageClass that is 1GB in size. It also is only mountable on one Node at a time (ReadWriteOnce) which is a characteristic of AWS EBS.
    1. `kubectl apply -f .` to deploy these YAML specs to our cluster
    1. `kubectl get pods` and see our new `storage-test-ebs` running
    1. `kubectl exec -it storage-test-ebs -- /bin/bash` to give us an interactive shell into the running Pod
    1. `df -h` to show us the mounted Volumes - you can see our 1GB volume mounted to /mnt/test as we requested.
    1. `exit` to return to the bastion's shell
1. Go to the EC2 Service in the AWS console
1. Go to Volumes on the left-hand side navigation pane
1. Sort by Size such that the 1GB volume we created is at the top of the list by clicking on the Size heading

So as you can see the EBS CSI Driver add-on, that the Quick Start set up for us, allows our cluster users to request PersistentVolumes on Kubernetes  and get new dedicated EBS volumes created automatically.


### EFS

Elastic File System (EFS) is a managed service that presents filesystems that can be mounted by NFS clients.

Unlike the EBS CSI Driver, the EFS CSI driver requires an EFS Filesytem to already exist and for us to tell it which one to use for as part of each StorageClass.

Create that in the AWS Console by:
1. Go to the EC2 service in the AWS Console
1. Click on `Security Groups` on the left-hand side navigation pane
1. Click the `Create security group` button
1. Name the security group `EFS`
1. Also type `EFS` in the Description
1. Pick the `EKSClusterStack/VPC` VPC in the VPC dropdown
1. Click the `Add rule` button in the Inbound rules section
1. Choose `NFS` in the Type dropdown
1. Choose `Anywhere-IPv4` in the Source dropdown
1. Click the `Create security group` button
1. Going to the EFS service in the AWS Console
1. Click the `Create file system` button
1. Click on the `Customize` button
1. Click the `Next` button
1. Choose the `EKSClusterStack/VPC` VPC from the dropdown list
1. Tick the X in the upper right of each of the 3 blue security groups
1. Choose the EFS security group (you can type EFS in the filter box) for each of the mount targets (click it to see it added to the list below the dropdown)
1. Once you see the EFS Security group listed 3 times (once under each AZ) click the `Next` button
1. Click the `Next` button again and then click the `Create` button
1. Make note of the File system ID starting fs- we'll need that in a moment.

Now to use the EFS CSI Driver within Kubernetes:
1. If you are not still in the SSM Session to the Bastion as in the previous section re-open that
1. If your terminal says sh-4.2$ instead of root@... then run a `sudo bash` command to become root
1. Run:
    1. `cd eks-quickstart-immersion/efs_example/`
    1. `nano efs-storageclass.yaml`
        1. Replace `<EFS file system ID>` with the file system ID from our EFS in the AWS console you noted above
        1. Do a Ctrl-X to exit
        1. Answer `Y` to the question as to whether to Save then press Enter/Return
    1. `cat efs-pod.yaml` and note how we create a PersistentVolumeClaim to say we want a new volume using that EFS StorageClass that is 1GB in size (EFS is unlimited so this is ignored but k8s requires it is there). It also is only mountable on multiple Nodes/Pods at once (ReadWriteMany) which is a characteristic of AWS EFS.
    1. `kubectl apply -f .` to deploy our manifests
    1. `kubectl get pods` and see our new `storage-test-efs` running
    1. `kubectl exec -it storage-test-efs -- /bin/bash` to give us an interactive shell into the running Pod
    1. `df -h` to show us the mounted Volumes - you can see our unlimited (it shows as 8 Exabytes!) volume mounted to /mnt/test as we requested.
    1. `exit` to return to the bastion's shell
1. Go to the EFS Service in the AWS Console
1. Go to `Access points` on the left-hand navigation pane
1. Note that the EFS CSI Driver created both a path for this PersistentVolumeClaim but an EFS Access point to control access to that path for us automatically.

So as you can see the EFS CSI Driver add-on, that the Quick Start set up for us, allows our cluster users to request PersistentVolumes on Kubernetes and get new dedicated EFS folders and associated Access points within our EFS Filesystem(s) created automatically.

## Demonstrate the Horizontal Pod Autoscaler (HPA) and the Cluster Autoscaler

### Horizontal Pod Autoscaler (HPA)

The Horizontal Pod Autoscaler (HPA) will increase or decrease the number of Pods that are running behind a ReplicaSet in response to metrics you specify like CPU.

The HPA is built in to Kubernetes and EKS - but it requires the metrics-server in order to function which is not. The metrics-server is also required for various other things like the `kubectl top` command to work. So, we deploy it as part of the Quick Start.

To demonstrate the HPA working there is a demo provided by Kubernetes described at https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale-walkthrough/

Have a look through that page describing the demo and then do it by:
1. If you are not still in the SSM Session to the Bastion as in the previous section re-open that
1. If your terminal says sh-4.2$ instead of root@... then run a `sudo bash` command to become root
1. Run:
  1. `kubectl apply -f https://k8s.io/examples/application/php-apache.yaml` to deploy the sample Deployment and Service that we want to autoscale
  1. `kubectl autoscale deployment php-apache --cpu-percent=50 --min=1 --max=10` to tell Kubernetes to scale up/down our Deployment targetting 50% CPU utilisation (i.e. scale up if above 50 and down if below 50)
  1. `kubectl describe hpa` to see/confirm the details of the autoscaling we asked for
  1. `kubectl run -it --rm load-generator --image=busybox /bin/sh` to run a new busybox container and connect to an interactive shell on it
  1. `while true; do wget -q -O- http://php-apache; done` to generate load against our service
1. Open another SSM Session to our Bastion from the EC2 service console
1. Run:
  1. `sudo bash`
  1. `kubectl describe hpa php-apache` and see that it has started to scale up the service
1. Go back to the origional Session Manager (with the flood of OK!s) and do a Ctrl-C to stop generating the load and type `exit`
1. If you run `kubectl describe hpa php-apache again` in a minute you'll see that it scales back down

### Cluster Autoscaler (CA)

If the Pods scale out enough then you need to also scale out your Nodes in order to have enough capacity to accommodate them - that is where the Cluster Autoscaler (CA) comes in.

By default (and as deployed in our Quick Start) it will add more Nodes (by increasing the desired capacity of their Auto Scaling Group (ASG) in AWS) when Pods can't be scheduled due to insufficient capacity.

To see this in action we'll deploy too many things for our cluster. To to that:
1. If you are not still in the SSM Session to the Bastion as in the previous section re-open that
1. If your terminal says sh-4.2$ instead of root@... then run a `sudo bash` command to become root
1. Run:
  1. `kubectl scale deployment ghost --replicas 20` which will tell kubernetes we now want 20 of our ghost Pods instead of our current 1. As these have 1vCPU and 1GB of RAM each we now need 20 vCPUs and 20GB of RAM.
  1. `kubectl get pods` to see all of the Pending Pods
1. If you wait a minute or two and then run `kubectl get nodes` you'll see more Nodes have launched and then, in turn, if you run `kubectl get pods` you'll see that more of the Pods have been able to launch onto those new Nodes
1. If you scale ghost back down with a `kubectl scale deployment ghost --replicas 2` the CA will scale the Nodes back down again eventually too.

We specified a Maximum of our Managed Node Group capacity of 4 which is why it stopped when it reached 4. This parameter be changed in the cdk.json file in `ee/cluster-bootstrap/`.

You can find out more about the use of Cluster Autoscaler in the EKS Documentation - https://docs.aws.amazon.com/eks/latest/userguide/cluster-autoscaler.html#ca-deployment-considerations