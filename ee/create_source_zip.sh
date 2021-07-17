#!/bin/bash
rm -rf source/ || true
rm source.zip || true
mkdir source
cp cluster-bootstrap/buildspec.yml source
sed -i '/cluster-bootstrap/d' source/buildspec.yml
cp cluster-bootstrap/eks_cluster.py source
cp cluster-bootstrap/cdk.json source
cp cluster-bootstrap/ekslogs_custom_resource.py source
cp cluster-bootstrap/requirements.txt source
cd source
zip -r ../source.zip . -x '*.git*' -x '*cdk.out*' -x '*.vscode*'