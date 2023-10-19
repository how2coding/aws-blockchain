  accept-invite.yaml

       AWSTemplateFormatVersion: 2010-09-09
    Description: AMB member invitation acceptance template
    Parameters:
      NetworkId:
        Description: The ID of the network that invited this new member
        AllowedPattern: "^[0-9a-zA-Z\\-]+$"
        Type: String
      InvitationId:
        Description: The ID of this new memberʼs invitation
        AllowedPattern: "^[0-9a-zA-Z\\-]+$"
        Type: String
      MemberName:
        Description: >-
          The name of the first member in your Amazon Managed Blockchain network.
        AllowedPattern: "^[0-9a-zA-Z]+$"
        ConstraintDescription: FirstMemberName must be alphanumeric.
        Type: String
      AdminUsername:
        Description: The user name of your first memberʼs admin user.
        AllowedPattern: "^[0-9a-zA-Z/]+$"
        ConstraintDescription: >-
          AdminUsername must contain only uppercase and lowercase letters and numbers.
        Type: String
      AdminPassword:
        Description: The password of your first memberʼs admin user.
        MinLength: 8
        MaxLength: 32
        AllowedPattern: "^(?!.*?['\"\\/ @])(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).*{8,32}$"
        ConstraintDescription: >-
          AdminPassword must be at least 8 characters long and must contain at least
          one uppercase character, one lowercase character, and one digit. It must
          not contain ', ", \, /, @ or spaces. It must not exceed 32 characters in
          length.
        Type: String
        NoEcho: true
      PeerNode1AZ:
        Description: The Availability Zone for your first peer node.
        Default: us-east-1a
        Type: String
      PeerNode2AZ:
        Description: The Availability Zone for your second peer node. Can be blank.
        Default: us-east-1b
        Type: String
      InstanceType:
        Description: The type of compute instance to use for your peer nodes.
        Default: bc.t3.small
        Type: String
        AllowedValues:
          - bc.t3.small
          - bc.t2.medium
    Resources:
      Member:
        Type: AWS::ManagedBlockchain::Member
        Properties:
          NetworkId: !Ref NetworkId
          InvitationId: !Ref InvitationId
          MemberConfiguration:
            Name: !Ref MemberName
            MemberFrameworkConfiguration:
              MemberFabricConfiguration:
                AdminUsername: !Ref AdminUsername
                AdminPassword: !Ref AdminPassword
      PeerNode1:
        Type: AWS::ManagedBlockchain::Node
        Properties:
          MemberId: !GetAtt Member.MemberId
          NetworkId: !GetAtt Member.NetworkId
          NodeConfiguration:
            AvailabilityZone: !Ref PeerNode1AZ
            InstanceType: !Ref InstanceType
      PeerNode2:
        Type: AWS::ManagedBlockchain::Node
        Properties:
          MemberId: !GetAtt Member.MemberId
          NetworkId: !GetAtt Member.NetworkId
          NodeConfiguration:
            AvailabilityZone: !Ref PeerNode2AZ
            InstanceType: !Ref InstanceType

# Deploy the CloudFormation Stack

    export AWS_DEFAULT_REGION=us-east-1
    export NETWORKID=$(aws managedblockchain list-invitations | jq -r '[.Invitations[] | select(.Status == "PENDING" and .NetworkSummary.Status == "AVAILABLE") | .NetworkSummary.Id][0]')
    export INVITATIONID=$(aws managedblockchain list-invitations | jq -r '[.Invitations[] | select(.Status == "PENDING" and .NetworkSummary.Status == "AVAILABLE") | .InvitationId][0]')
    cd ~/environment
    aws cloudformation deploy --template-file accept-invite.yaml --stack-name amb-supplier --parameter-overrides NetworkId=$NETWORKID InvitationId=$INVITATIONID MemberName=Supplier AdminUsername=spadmin AdminPassword=Admin123 PeerNode1AZ=us-east-1a PeerNode2AZ=us-east-1b InstanceType=bc.t3.small




### Create a Cloud9 environment

    sudo pip install awscli --upgrade
    sudo yum install -y jq
    aws configure set default.region us-east-1

### .

    SIZE=${1:-40}
    INSTANCEID=$(curl http://169.254.169.254/latest/meta-data//instance-id)
    VOLUMEID=$(aws ec2 describe-instances \
      --instance-id $INSTANCEID \
      --query "Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId" \
      --output text)
    
    aws ec2 modify-volume --volume-id $VOLUMEID --size $SIZE
    while [ \
      "$(aws ec2 describe-volumes-modifications \
        --volume-id $VOLUMEID \
        --filters Name=modification-state,Values="optimizing","completed" \
        --query "length(VolumesModifications)"\
        --output text)" != "1" ]; do
    sleep 1
    done
    
    if [ $(readlink -f /dev/xvda) = "/dev/xvda" ]
    then
      sudo growpart /dev/xvda 1
      sudo xfs_growfs /dev/xvda1
    else
      sudo growpart /dev/nvme0n1 1
      sudo xfs_growfs /dev/nvme0n1p1
    fi

### .

    export RETAILER_AWS_ID=123456789012
    export SUPPLIER_AWS_ID=123456789013
### .

    export MEMBER_NAME='Retailer'

### .

    export MEMBER_NAME='Supplier'

### .

    echo "export MEMBER_NAME='$MEMBER_NAME'" >> ~/.bash_profile
    echo "export RETAILER_AWS_ID=$RETAILER_AWS_ID" >> ~/.bash_profile
    echo "export SUPPLIER_AWS_ID=$SUPPLIER_AWS_ID" >> ~/.bash_profile
    echo "export THIS_AWS_ID=\$(case \$MEMBER_NAME in Retailer) echo $RETAILER_AWS_ID;; Supplier) echo $SUPPLIER_AWS_ID;; esac)" >> ~/.bash_profile
    source ~/.bash_profile

### # IAM Configuration

    cat <<EOT > ~/amb-access-policy.json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "ListNetworkMembers",
          "Effect": "Allow",
          "Action": [
              "managedblockchain:GetNetwork",
              "managedblockchain:ListMembers"
          ],
          "Resource": [
              "arn:aws:managedblockchain:*:$THIS_AWS_ID:networks/*"
          ]
        },
        {
          "Sid": "ManageNetworkResources",
          "Effect": "Allow",
          "Action": [
            "managedblockchain:CreateProposal",
            "managedblockchain:GetProposal",
            "managedblockchain:DeleteMember",
            "managedblockchain:VoteOnProposal",
            "managedblockchain:ListProposals",
            "managedblockchain:GetNetwork",
            "managedblockchain:ListMembers",
            "managedblockchain:ListProposalVotes",
            "managedblockchain:RejectInvitation",
            "managedblockchain:GetNode",
            "managedblockchain:GetMember",
            "managedblockchain:DeleteNode",
            "managedblockchain:CreateNode",
            "managedblockchain:CreateMember",
            "managedblockchain:ListNodes"
          ],
          "Resource": [
            "arn:aws:managedblockchain:*::networks/*",
            "arn:aws:managedblockchain:*::proposals/*",
            "arn:aws:managedblockchain:*:$THIS_AWS_ID:members/*",
            "arn:aws:managedblockchain:*:$THIS_AWS_ID:invitations/*",
            "arn:aws:managedblockchain:*:$THIS_AWS_ID:nodes/*"
          ]
        },
        {
          "Sid": "WorkWithNetworksForAcct",
          "Effect": "Allow",
          "Action": [
            "managedblockchain:ListNetworks",
            "managedblockchain:ListInvitations",
            "managedblockchain:CreateNetwork"
          ],
          "Resource": "*"
        }
      ]
    }
    EOT


### .

    aws iam create-policy --policy-name AmazonManagedBlockchainControl --policy-document file://$HOME/amb-access-policy.json | jq -r .Policy.Arn
###  Install linux packages

    sudo yum update -y
    sudo yum install -y telnet jq git libtool
    wget https://dl.google.com/go/go1.16.7.linux-amd64.tar.gz -O go1.16.7.linux-amd64.tar.gz
    tar -xzf go1.16.7.linux-amd64.tar.gz --overwrite
    sudo rsync -a go /usr/local
    sudo yum install libtool-ltdl-devel -y

### Configure environment


    cd
    add_line_to_profile_if_not_there() { grep -qxF "$1" .bash_profile || echo "$1" >> .bash_profile; }
    export line="export GOPATH=\"\$HOME/go\""
    add_line_to_profile_if_not_there "$line"
    export line="export GOROOT=/usr/local/go"
    add_line_to_profile_if_not_there "$line"
    export line="export PATH=\"\$GOROOT/bin:\$PATH\""
    add_line_to_profile_if_not_there "$line"
    export line="export PATH=\"\$PATH:\$HOME/go/src/github.com/hyperledger/fabric-ca/bin\""
    add_line_to_profile_if_not_there "$line"
    export line="export MEMBER_NAME='$MEMBER_NAME'"
    add_line_to_profile_if_not_there "$line"
    export line="export MEMBER_ABBREVIATION=\$(case \$MEMBER_NAME in Retailer) echo 'rt';; Supplier) echo 'sp';; esac)"
    add_line_to_profile_if_not_there "$line"
    export line="export MEMBER_ADMIN=\$(case \$MEMBER_NAME in Retailer) echo 'rtadmin';; Supplier) echo 'spadmin';; esac)"
    add_line_to_profile_if_not_there "$line"
    export line="export WORKER1_NAME=\$(case \$MEMBER_NAME in Retailer) echo 'rtworker';; Supplier) echo 'spworker';; esac)"
    add_line_to_profile_if_not_there "$line"
    export line="export WORKER1_PERMISSIONS=\$(case \$MEMBER_NAME in Retailer) echo 'receive_label';; Supplier) echo 'manufacture_ship';; esac)"
    add_line_to_profile_if_not_there "$line"
    export line="export WORKER2_NAME=\$(case \$MEMBER_NAME in Retailer) echo 'rtseller';; Supplier) echo 'spinspector';; esac)"
    add_line_to_profile_if_not_there "$line"
    export line="export WORKER2_PERMISSIONS=\$(case \$MEMBER_NAME in Retailer) echo 'sell';; Supplier) echo 'inspect';; esac)"
    add_line_to_profile_if_not_there "$line"
    export line="export AWS_DEFAULT_REGION=\$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -c -r .region)"
    add_line_to_profile_if_not_there "$line"
    export line="export NETWORKID=\$(aws managedblockchain list-networks | jq -r '.Networks[] | select(.Name == \"SupplyChain\").Id')"
    add_line_to_profile_if_not_there "$line"
    export line="export ORDERER=\$(aws managedblockchain get-network --network-id \$NETWORKID | jq -r .Network.FrameworkAttributes.Fabric.OrderingServiceEndpoint)"
    add_line_to_profile_if_not_there "$line"
    export line="export ORDERERNOPORT=\$(echo \$ORDERER | cut -f1 -d':')"
    add_line_to_profile_if_not_there "$line"
    export line="export MEMBERID=\$(aws managedblockchain list-members --network-id \$NETWORKID | jq -r \".Members[] | select(.Name == \\\"\$MEMBER_NAME\\\") | .Id\")"
    add_line_to_profile_if_not_there "$line"
    export line="export BUCKET_NAME=\$(echo \$NETWORKID | tr '[:upper:]' '[:lower:]')-certs"
    add_line_to_profile_if_not_there "$line"
    export line="export MEMBER_AWS_ID=$(aws sts get-caller-identity --query Account --output text)"
    add_line_to_profile_if_not_there "$line"
    export line="export RETAILER_AWS_ID=$RETAILER_AWS_ID"
    add_line_to_profile_if_not_there "$line"
    export line="export SUPPLIER_AWS_ID=$SUPPLIER_AWS_ID"
    add_line_to_profile_if_not_there "$line"
    export line="export RETAILERID=\$(aws managedblockchain list-members --network-id \$NETWORKID | jq -r \".Members[] | select(.Name == \\\"Retailer\\\") | .Id\")"
    add_line_to_profile_if_not_there "$line"
    export line="export SUPPLIERID=\$(aws managedblockchain list-members --network-id \$NETWORKID | jq -r \".Members[] | select(.Name == \\\"Supplier\\\") | .Id\")"
    add_line_to_profile_if_not_there "$line"
    export line="export CASERVICEENDPOINT=\$(aws managedblockchain get-member --network-id \$NETWORKID --member-id \$MEMBERID | jq -r .Member.FrameworkAttributes.Fabric.CaEndpoint)"
    add_line_to_profile_if_not_there "$line"
    export line="export PEER1ID=\$(aws managedblockchain list-nodes --network-id \$NETWORKID --member-id \$MEMBERID | jq -r \"[.Nodes[] | select(.Status == \\\"AVAILABLE\\\")][0].Id\")"
    add_line_to_profile_if_not_there "$line"
    export line="export PEER2ID=\$(aws managedblockchain list-nodes --network-id \$NETWORKID --member-id \$MEMBERID | jq -r \"[.Nodes[] | select(.Status == \\\"AVAILABLE\\\")][1].Id\")"
    add_line_to_profile_if_not_there "$line"
    export line="export PEER1ENDPOINT=\$(aws managedblockchain get-node --network-id \$NETWORKID --member-id \$MEMBERID --node-id \$PEER1ID | jq -r .Node.FrameworkAttributes.Fabric.PeerEndpoint)"
    add_line_to_profile_if_not_there "$line"
    export line="export PEER1ENDPOINTNOPORT=\$(echo \$PEER1ENDPOINT | cut -f1 -d':')"
    add_line_to_profile_if_not_there "$line"
    export line="export PEER1EVENTENDPOINT=\$(aws managedblockchain get-node --region \$AWS_DEFAULT_REGION --network-id \$NETWORKID --member-id \$MEMBERID --node-id \$PEER1ID --query 'Node.FrameworkAttributes.Fabric.PeerEventEndpoint' --output text)"
    add_line_to_profile_if_not_there "$line"
    export line="export PEER2ENDPOINT=\$(aws managedblockchain get-node --network-id \$NETWORKID --member-id \$MEMBERID --node-id \$PEER2ID | jq -r .Node.FrameworkAttributes.Fabric.PeerEndpoint)"
    add_line_to_profile_if_not_there "$line"
    export line="export PEER2ENDPOINTNOPORT=\$(echo \$PEER2ENDPOINT | cut -f1 -d':')"
    add_line_to_profile_if_not_there "$line"
    export line="export PEER2EVENTENDPOINT=\$(aws managedblockchain get-node --region \$AWS_DEFAULT_REGION --network-id \$NETWORKID --member-id \$MEMBERID --node-id \$PEER2ID --query 'Node.FrameworkAttributes.Fabric.PeerEventEndpoint' --output text)"
    add_line_to_profile_if_not_there "$line"
    export line="export TEST_CHANNEL_NAME=\$(echo \$MEMBER_NAME | tr '[:upper:]' '[:lower:]')channel"
    add_line_to_profile_if_not_there "$line"

### .

    source ~/.bash_profile

### .
# Verify configuration

    env | sort

    curl "https://$CASERVICEENDPOINT/cainfo" -k -s | jq

# Setup Fabric binaries

    cd
    curl -sSL http://bit.ly/2ysbOFE | bash -s -- 2.2.4 1.5.2 -d -s
    mv config/core.yaml . && rm -r config

    peer version
    fabric-ca-client version

### .

    cd
    add_line_to_profile_if_not_there() { grep -qxF "$1" .bash_profile || echo "$1" >> .bash_profile; }
    export line="export CORE_PEER_TLS_ENABLED=true"
    add_line_to_profile_if_not_there "$line"
    export line="export CORE_PEER_TLS_ROOTCERT_FILE=\"\$HOME/managedblockchain-tls-chain.pem\""
    add_line_to_profile_if_not_there "$line"
    export line="export CORE_PEER_LOCALMSPID=\"\$MEMBERID\""
    add_line_to_profile_if_not_there "$line"
    export line="export CORE_PEER_MSPCONFIGPATH=\"\$HOME/admin-msp\""
    add_line_to_profile_if_not_there "$line"
    export line="export CORE_PEER_ADDRESS=\"\$PEER1ENDPOINT\""
    add_line_to_profile_if_not_there "$line"

### .

    source ~/.bash_profile

# Enroll Fabric admin

    aws s3 cp s3://$AWS_DEFAULT_REGION.managedblockchain/etc/managedblockchain-tls-chain.pem ~/managedblockchain-tls-chain.pem

### .

    openssl x509 -noout -text -in ~/managedblockchain-tls-chain.pem

### .

    cd
    fabric-ca-client enroll -u https://$MEMBER_ADMIN\:Admin123@$CASERVICEENDPOINT --tls.certfiles ~/managedblockchain-tls-chain.pem -M admin-msp -H $HOME
    cp -r ~/admin-msp/signcerts ~/admin-msp/admincerts


### .

# Chaincode development environment

    cd
    nvm install 12.16.1
    nvm use 12.16.1
    nvm alias default 12.16.1
    mkdir ~/environment/chaincode
    touch ~/environment/chaincode/package.json
    touch ~/environment/chaincode/products.js
    touch ~/environment/chaincode/products_test.js

### package.json

    {
      "name": "chaincode",
      "version": "1.0.0",
      "scripts": {
        "test": "NODE_PATH=lib mocha *_test.js",
        "start": "NODE_PATH=lib node products.js"
      },
      "dependencies": {
        "fabric-shim": "^2.0.0",
        "javascript-state-machine": "^3.1.0",
        "loglevel": "^1.6.8"
      },
      "devDependencies": {
        "@theledger/fabric-mock-stub": "^2.0.3",
        "chai": "^4.2.0",
        "chai-as-promised": "^7.1.1",
        "chai-datetime": "^1.6.0",
        "moment": "^2.25.3"
      }
    }


### .

    npm install mocha@7.2.0 -g
    cd ~/environment/chaincode && npm i

### # Write chaincode

### products.js

    /*
    # Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
    # 
    # Licensed under the Apache License, Version 2.0 (the "License").
    # You may not use this file except in compliance with the License.
    # A copy of the License is located at
    # 
    #     http://www.apache.org/licenses/LICENSE-2.0
    # 
    # or in the "license" file accompanying this file. This file is distributed 
    # on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
    # express or implied. See the License for the specific language governing 
    # permissions and limitations under the License.
    #
    */
    'use strict';
    
    const shim = require('fabric-shim');
    const log = require('loglevel').getLogger('products');
    log.setLevel('trace');
    const StateMachine = require('javascript-state-machine');
    
    
    ////////////////////////////////////////////////////////////////////////////
    // FSM (Finite State Machine)
    // Used to ensure state transitions are valid
    ////////////////////////////////////////////////////////////////////////////
    
    const FSM = new StateMachine.factory({
      init: 'manufactured',
      transitions: [
        { name: 'inspect', from: 'manufactured', to: 'inspected' }, // supplier
        { name: 'ship', from: 'inspected', to: 'shipped' },         // supplier
        { name: 'receive', from: 'shipped', to: 'stocked' },        // retailer
        { name: 'label', from: 'stocked', to: 'labeled' },          // retailer
        { name: 'sell', from: 'labeled', to: 'sold' },              // retailer
        { name: 'goto', from: '*', to: function(s) { return s } }
      ]
    });
    
    ////////////////////////////////////////////////////////////////////////////
    // ProductsChaincode
    // Used to track all products in the supply chain
    ////////////////////////////////////////////////////////////////////////////
    
    const ProductsChaincode = class {
      constructor(cid = shim.ClientIdentity) {
        this.clientIdentity = cid;
      }
    
      ////////////////////////////////////////////////////////////////////////////
      // requireAffiliationAndPermissions
      // Checks that invoke() caller belongs to the specified blockchain member
      // and has the specified permission. Throws an exception if not.
      ////////////////////////////////////////////////////////////////////////////
    
      requireAffiliationAndPermissions(stub, affiliation, permission) {
        const cid = new this.clientIdentity(stub);
        let permissions = cid.getAttributeValue('permissions') || 'default';
        permissions = permissions.split('_');
        const hasBoth =
          cid.assertAttributeValue('hf.Affiliation', affiliation) &&
          permissions.includes(permission);
        if (!hasBoth) {
          const msg = `Unauthorized access: affiliation ${affiliation}` +
            ` and permission ${permission} required`;
          throw new Error(msg);
        }
      }
    
      ////////////////////////////////////////////////////////////////////////////
      // assertCanPerformOperation
      // Determines which membership affiliations are required for which
      // operations. Called by other methods. Calls
      // requireAffiliationAndPermissions as a subroutine.
      ////////////////////////////////////////////////////////////////////////////
    
      assertCanPerformTransition(stub, transition) {
        let requiredAffiliation = 'undefined';
        switch (transition) {
          case 'manufacture':
          case 'inspect':
          case 'ship': requiredAffiliation = 'Supplier'; break;
          case 'receive':
          case 'label':
          case 'sell': requiredAffiliation = 'Retailer';
        }
        this.requireAffiliationAndPermissions(stub, requiredAffiliation, transition);
      }
    
      ////////////////////////////////////////////////////////////////////////////
      // Initialize the chaincode
      ////////////////////////////////////////////////////////////////////////////
    
      async Init(stub) {
        const ret = stub.getFunctionAndParameters();
        if (ret.params.length > 0) {
          return shim.error('Init() does not expect any arguments');
        }
        // initialize list of all product IDs so that they can be iterated over
        await stub.putState('productIDs', Buffer.from('[]'));
        return shim.success();
      }
    
      ////////////////////////////////////////////////////////////////////////////
      // Invoke chaincode and dispatch the appropriate method
      ////////////////////////////////////////////////////////////////////////////
    
      async Invoke(stub) {
        const ret = stub.getFunctionAndParameters();
        log.debug(ret);
    
        if (!ret.fcn) {
          return shim.error('Missing method parameter in invoke');
        }
    
        let method = this[ret.fcn];
        let returnval;
    
        if (!method) {
          return shim.error(`Unrecognized method ${ret.fcn} in invoke`);
        }
        try {
          let payload = await method(this, stub, ret.params);
          log.debug(`Payload from call to ${ret.fcn} was ${JSON.stringify(payload)}.`);
          returnval = shim.success(Buffer.from(payload));
        } catch (err) {
          log.error(`Error in Invoke ${ret.fcn}: ${err.message}`);
          returnval = shim.error(Buffer.from(err.message));
        }
        log.debug(`exiting Invoke`)
        return returnval;
      }
    
      ////////////////////////////////////////////////////////////////////////////
      // createProduct
      // Add a newly-manufactured product to the blockchain
      ////////////////////////////////////////////////////////////////////////////
    
      async createProduct(self, stub, args) {
        log.debug(`in createProduct(self, stub, ${JSON.stringify(args)})...`);
        if (args.length !== 1) {
          throw new Error('createProduct expects one argument');
        }
    
        self.assertCanPerformTransition(stub, 'manufacture');
        const now = new Date();
        const payload = {
          "state": "manufactured",
          "history": {
            "manufactured": now.toISOString()
          }
        };
        const strPayload = JSON.stringify(payload);
        const productId = args[0];
        const key = `product_${productId}`;
        let productStateBytes = await stub.getState(key);
    
        if (!productStateBytes || productStateBytes.length === 0) {
          log.debug(`Calling stub.putState(${key}, Buffer.from(JSON.stringify(${strPayload})))...`);
          await stub.putState(key, Buffer.from(strPayload));
        } else {
          throw new Error('Product with same ID already exists.');
        }
    
        // add productID to list of product IDs
        log.debug(`Retrieving product ID list...`);
        let arr = await stub.getState('productIDs');
        log.debug(`product ID list, ${arr}`);
        let productIDs = JSON.parse(arr.toString());
        log.debug(`product ID list JSON string, ${productIDs}`);
        productIDs = [...productIDs, key].sort();
        log.debug(`Storing updated product ID list...`);
        await stub.putState('productIDs', Buffer.from(JSON.stringify(productIDs)));
    
        log.debug(`exiting createProduct(self, stub, ${JSON.stringify(args)})...`);
        return strPayload;
      }
    
      ////////////////////////////////////////////////////////////////////////////
      // updateProductState
      // Update an existing product as it moves through the supply chain
      ////////////////////////////////////////////////////////////////////////////
    
      async updateProductState(self, stub, args) {
        if (args.length !== 2) {
          throw new Error('updateProductState expects two arguments');
        }
        const productId = args[0];
        const transition = args[1];
        self.assertCanPerformTransition(stub, transition);
        const key = `product_${productId}`;
        const productDataBytes = await stub.getState(key);
        const productData = JSON.parse(productDataBytes.toString());
        const product = new FSM();
        product.goto(productData.state);
        product[transition]();
        productData.state = product.state;
        const now = new Date();
        productData.history = productData.history || {};
        productData.history[product.state] = now.toISOString();
        const stringProductData = JSON.stringify(productData);
        await stub.putState(key, Buffer.from(stringProductData));
        return stringProductData;
      }
    
    
      ////////////////////////////////////////////////////////////////////////////
      // query blockchain state
      ////////////////////////////////////////////////////////////////////////////
    
      async query() {
        const params = Array.from(arguments);
        let ctx, stub, args, keyIndex = 0, expectedArgLength = 1;
        if (params.length === 2) { // we're being called in unit tests
          [stub, args] = params;
          keyIndex = 1;
          expectedArgLength = 2;
        } else {                   // we're being called in a live environment
          [ctx, stub, args] = params;
        }
        if (args.length !== expectedArgLength) {
          throw new Error(`Incorrect number of arguments. Arguments contains: ${JSON.stringify(args)}`);
        }
    
        let key = args[keyIndex];
    
        // Get the state from the ledger
        let resultBytes = await stub.getState(key);
        if (!resultBytes) {
          const message = `No value for key ${key}`;
          throw new Error(message);
        }
    
        log.debug('Query Response:', resultBytes.toString());
        return resultBytes;
      }
    };
    
    module.exports = ProductsChaincode;
    
    if (require.main === module) {
      shim.start(new ProductsChaincode());
    }

### products_test.js

    /*
    # Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
    # 
    # Licensed under the Apache License, Version 2.0 (the "License").
    # You may not use this file except in compliance with the License.
    # A copy of the License is located at
    # 
    #     http://www.apache.org/licenses/LICENSE-2.0
    # 
    # or in the "license" file accompanying this file. This file is distributed 
    # on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
    # express or implied. See the License for the specific language governing 
    # permissions and limitations under the License.
    #
    */
    'use strict';
    
    const chai = require('chai');
    const chaiAsPromised = require('chai-as-promised');
    const chaiDateTime = require('chai-datetime');
    chai.use(chaiAsPromised);
    chai.use(chaiDateTime);
    const expect = chai.expect;
    const moment = require('moment');
    
    const ProductsChaincode = require('./products');
    const MockStub = require('@theledger/fabric-mock-stub');
    const { ChaincodeMockStub } = MockStub;
    const log = require('loglevel').getLogger('products');
    const log_level = process.env['LOG_LEVEL'] || 'warn';
    log.setLevel(log_level.toUpperCase());
    
    
    ////////////////////////////////////////////////////////////////////////////
    // suppressLogging
    // helper function to turn off logging during tests
    // that are supposed to produce errors
    ////////////////////////////////////////////////////////////////////////////
    
    const suppressLogging = async (func) => {
      const previousLevel = log.getLevel();
      log.setLevel(log.levels.SILENT);
      await func();
      log.setLevel(previousLevel);
    };
    
    
    ////////////////////////////////////////////////////////////////////////////
    // spCIDMock
    // Mock used to imitate the behavior of the ClientIdentity object.
    ////////////////////////////////////////////////////////////////////////////
    
    class spCIDMock {
      constructor(stub) {
        this._attributes = {
          'hf.Affiliation': 'Supplier',
          'permissions': 'manufacture'
        };
      }
      getAttributeValue(key) { return this._attributes[key]; }
      assertAttributeValue(key, value) { return this._attributes[key] === value; }
    }
    
    
    describe('Products', () => {
      let chaincode, stub;
    
      beforeEach(() => {
        chaincode = new ProductsChaincode();
        stub = new ChaincodeMockStub("ProductsMockStub", chaincode);
      });
    
      describe('init', () => {
        it("should succeed", async () => {
          const response = await stub.mockInit('tx1', []);
          expect(response.status).to.eql(200);
        });
    
        it("should initialize the ProductIDs list", async () => {
          let response = await stub.mockInit('tx1', []);
          response = await chaincode.query(stub, ['query', 'productIDs']);
          expect(response.toString()).to.eql('[]');
        });
    
        it("should expect no arguments", async () => {
          const response = await stub.mockInit('tx1', ['fn', 'invalid']);
          expect(response.status).to.eql(500);
          expect(response.message).to.eql('Init() does not expect any arguments');
        });
      });
    
      describe('invoke', () => {
        it('should reject unrecognized commands', async () => {
          const response = await stub.mockInvoke('tx1', ['blah']);
          expect(response.status).to.eql(500);
          expect(response.message).to.eql('Unrecognized method blah in invoke');
        });
    
        it('should reject invocations with no arguments', async () => {
          const response = await stub.mockInvoke('tx1', []);
          expect(response.status).to.eql(500);
          expect(response.message).to.eql('Missing method parameter in invoke');
        });
      });
    
      describe('query', () => {
        beforeEach(async () => {
          chaincode = new ProductsChaincode(spCIDMock);
          stub = new ChaincodeMockStub("ProductsMockStub", chaincode);
          await stub.mockInit('tx1', []);
        });
    
        it('should throw an error if called with too many arguments', async () => {
          await expect(chaincode.query(stub, ['query', 'product_1', 'product_2']))
            .to.eventually.be.rejected.and.match(/Incorrect number of arguments/m);
        });
    
        it('should throw an error if a key is not found', async () => {
          await expect(chaincode.query(stub, ['query', 'product_1']))
            .to.eventually.be.rejected.and.match(/No value for key/m);
        });
    
        it('should return an empty array for productIDs', async () => {
          const response = await chaincode.query(stub, ['query', 'productIDs']);
          expect(response.toString()).to.eql('[]');
        });
      });
    
      describe('createProduct', () => {
        beforeEach(async () => {
          chaincode = new ProductsChaincode(spCIDMock);
          stub = new ChaincodeMockStub("ProductsMockStub", chaincode);
          await stub.mockInit('tx1', []);
        });
    
        it("should only accept one argument", async () => {
          suppressLogging(async () => {
            await expect(stub.mockInvoke('tx2', ['createProduct', '1', 'extra']))
              .to.eventually.have.property('message')
              .and.match(/createProduct expects one argument/m);
          });
        });
    
        it("should not overwrite an existing product with the same ID", async () => {
          await stub.mockInvoke('tx2', ['createProduct', '1']);
          suppressLogging(async () => {
            await expect(stub.mockInvoke('tx3', ['createProduct', '1']))
              .to.eventually.have.property('message')
              .and.match(/Product with same ID already exists/m);
          });
        });
    
        it("should set new products' state to 'manufactured'", async () => {
          let response = await stub.mockInvoke('tx2', ['createProduct', '1']);
          response = await chaincode.query(stub, ['query', 'product_1']);
          expect(JSON.parse(response.toString())).to.have.property('state', 'manufactured');
        });
    
        it('should add an element to the list of productIDs', async () => {
          await stub.mockInit('tx2', []);
          let response = await stub.mockInvoke('tx3', ['createProduct', '1']);
          response = await chaincode.query(stub, ['query', 'productIDs']);
          expect(response.toString()).to.equal('["product_1"]');
        });
    
        it('should not allow clients without the appropriate permissions', async () => {
          const productID = '1';
          chaincode = new ProductsChaincode();
          stub = new ChaincodeMockStub("ProductsMockStub", chaincode);
          await stub.mockInit('tx1', []);
          async () => {
            await expect(stub.mockInvoke('tx2', ['createProduct', productID]))
              .to.eventually.have.property('message')
              .and.match(/affiliation Supplier and permission manufacture required/m);
          };
        });
      });
    
      describe('updateProductState', () => {
        const productID = '1';
        let chaincode, stub;
    
        beforeEach(async () => {
          chaincode = new ProductsChaincode();
          stub = new ChaincodeMockStub("ProductsMockStub", chaincode);
        });
    
        it('should only accept two arguments', async () => {
          chaincode = new ProductsChaincode(spCIDMock);
          stub = new ChaincodeMockStub("ProductsMockStub", chaincode);
          await stub.mockInit('tx1', []);
          const args = [
            'updateProductState',
            productID,
            'arrivedAtSupplier',
            'invalid'
          ];
          suppressLogging(async () => {
            await expect(stub.mockInvoke('tx3', args))
              .to.eventually.have.property('message')
              .and.match(/updateProductState expects two arguments/m);
          });
        });
    
        it('should not allow invalid state transitions', async () => {
          class cidMock {
            constructor(stub) {
              this._attributes = {
                'hf.Affiliation': 'Supplier',
                'permissions': 'manufacture_ship'
    
              };
            }
            getAttributeValue(key) { return this._attributes[key]; }
            assertAttributeValue(key, value) { return this._attributes[key] === value; }
          }
          chaincode = new ProductsChaincode(cidMock);
          stub = new ChaincodeMockStub("ProductsMockStub", chaincode);
          await stub.mockInit('tx1', []);
          const args = ['updateProductState', productID, 'ship'];
          await stub.mockInvoke('tx2', ['createProduct', productID]);
          suppressLogging(async () => {
            let result = await stub.mockInvoke('tx3', args);
            expect(result.message.toString()).to.eql('transition is invalid in current state');
          });
        });
    
        it('should store a history of timestamped state transitions', async () => {
          class cidMock {
            constructor(stub) {
              this._attributes = {
                'hf.Affiliation': 'Supplier',
                'permissions': 'manufacture_inspect'
              };
            }
            getAttributeValue(key) { return this._attributes[key]; }
            assertAttributeValue(key, value) { return this._attributes[key] === value; }
          }
          chaincode = new ProductsChaincode(cidMock);
          stub = new ChaincodeMockStub("ProductsMockStub", chaincode);
          await stub.mockInit('tx1', []);
          await stub.mockInvoke('tx2', ['createProduct', productID]);
          await stub.mockInvoke('tx3', ['updateProductState', productID, 'inspect']);
          const response = await chaincode.query(stub, ['query', 'product_1']);
          const expectedTime = new Date();
          const parsedResponse = JSON.parse(response.toString());
          expect(parsedResponse).to.have.property('history');
          const time = moment(parsedResponse.history.inspected).toDate();
          expect(time).to.be.closeToTime(expectedTime, 1);
        });
    
        it('should not allow clients without the appropriate permissions', async () => {
          chaincode = new ProductsChaincode(spCIDMock);
          stub = new ChaincodeMockStub("ProductsMockStub", chaincode);
          await stub.mockInit('tx1', []);
          await stub.mockInvoke('tx2', ['createProduct', productID]);
          const args = ['updateProductState', productID, 'inspect'];
          suppressLogging(async () => {
            let result = await stub.mockInvoke('tx3', args);
            expect(result.message.toString()).to.match(/affiliation Supplier and permission inspect required/);
          });
        });
      });
    });
    
    
    
    
    ### .
    
        mv node_modules/ lib
    
    ### .
    
        nvm use 12.16.1
        cd ~/environment/chaincode
        npm test

### # Create sharing policy

    echo $AWS_DEFAULT_REGION
### .

```

    
    aws configure
    `

<!--stackedit_data:
eyJoaXN0b3J5IjpbMTMxNjQxOTA4OCwxMjc3ODA5NDE0XX0=
-->