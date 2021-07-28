# EKS Quick Start (CDK - Python) Workshop

## Explore the CDK environment that has already been deployed into the account for you

In the interests of time we have already deployed the EKS Quick Start into this account for you. This process takes a little under 30 minutes end-to-end. You can see the template which deployed it in `ee/cluster-bootstrap/eks_cluster.py` and some of the parameters that it references are stored in `ee/cluster-bootstrap/cdk.json`.

If you want to see how long it actually took it was deployed via CodeBuild which ran the `cdk deploy` command for us:
* Go the AWS Console
* Go to the CodeBuild Service
* Go to build history on the left-hand navigation bar
* Note the time under `Duration`
* To see the logs of the process click on the link under `Build run`
* Scroll down to see the log output of the build process

### Exploring ee/cluster-bootstrap/eks_cluster.py

A few noteworthy things in our template that CDK makes easy:


### Have a look through the EKS console at our console and workloads

* Go to the EKS Service in the AWS Console (use the search box at the top of the page)
* 

### Use SSM Session Manager to connect to our Bastion/Jumpbox and run kubectl

* Go to the EC2 Service in the AWS Console
* Click on `Instances` on the left hand navigation pane
* Put a tick next to the Instance named `EKSClusterStack/BastionInstance
* Click the `Connect` button above the list
* Go to the `Session Manager` tab and click the `Connect` button
* Run `sudo bash` to become root (as we installed various things via UserData which runs as root)
* Run `kubectl get nodes -o wide` to see the Instances our Managed Node Group has provisioned for our cluster (-o changes the output format and wide tells it to show us some more detail)
* Run `kubectl get pods -A` to see all the Pods currently running on our cluster in all Namespaces (-A is the equivalent to --all-namespaces)
    * This gives you a sense of all the add-ons that the Quick Start has set up on our cluster for us. If this was a new EKS cluster without the Quick Start you'd only see three things (kube-proxy, coredns and aws-node (our CNI)). 
    * Also note all the Add-ons we've deployed we've put in the kube-system namespace so you'll need to specify that if you want to interact with these

## Install Ghost via another loosely coupled CDK Stack

* If you are not still in the SSM Session to the Bastion as in the previous section re-open that
* If your terminal says sh-4.2$ instead of root@... then run a `sudo bash` command to become root
* Run:
    * `cd ~`
    * `git clone https://github.com/jasonumiker/eks-quickstart-immersion.git`
    * 

## Check out the included observability components (Prometheus/Grafana and AWS Elasticsearch/Kibana)

## Demonstrate EBS and EFS PersistentVolumes via the included CSI Driver

## Demonstrate the Horizontal Pod Autoscaler (HPA) and the Cluster Autoscaler

## (Optional - if finished the workshop quickly - takes awhile) Upgrading our EKS and the Managed Node Group to 1.21 via the AWS console

As you may have seen in the banners in the Console there is an upgrade available for the cluster (it is version 1.20 and it can go to 1.21). In order to upgrade the cluster via the CDK there are two steps: