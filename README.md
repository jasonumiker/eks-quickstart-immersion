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

### Exploring ee/cluster-bootstrap/eks_cluster.py

A few noteworthy things in our template that CDK makes easy:

[TODO copy/paste in interesting stuff from the bootrap CDK .py]

### Have a look through the EKS console at our console and workloads

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

### Understanding what is actually happening while we wait for it to complete

When we run our `ghost_example.py` CDK template there are both AWS and Kubernetes components that CDK provisions for us.
![Git Flow Diagram](diagram1.PNG?raw=true "Git Flow Diagram")

We are also adding a new controller/operator to Kubernetes - [kubernetes-external-secrets]() - which is UPSERTing the AWS Secrets Manager secret that CDK is creating into Kubernetes so that we can easily consume this in our Pod(s). This joins the existing [AWS Load Balancer Controller]() which turns our Ingress Specs into an integration/delegation to the AWS Applicaiton Load Balancer (ALB).
![Operator Flow Diagram](diagram2.PNG?raw=true "Operator Flow Diagram")

TODO copy and paste examples of how to cross-reference the CDK stacks/objects and how it imports the kube manifest files rather than having you copy/paste them into the template.

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

### AWS Managed Elasticsearch and Kibana

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

## (Optional - if finished the workshop quickly - takes awhile) Upgrading our EKS and then the Managed Node Group to 1.21

As you may have seen in the banners in the Console there is an upgrade available for the cluster (it is version 1.20 and it can go to 1.21). In order to upgrade the cluster via the CDK there are two steps: