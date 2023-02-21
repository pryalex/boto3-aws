import boto3
import os

from botocore.config import Config

my_config = Config(
    region_name = 'eu-west-2',
    signature_version = 'v4',
    retries = {
        'max_attempts': 10,
        'mode': 'standard'
    }
)

client = boto3.client('kinesis', config=my_config)

client = boto3.client(
    'ec2',
    config=my_config,
    aws_access_key_id=os.environ['aws_access_key_id'],
    aws_secret_access_key=os.environ['aws_secret_access_key']
)
client_elb = boto3.client(
    'elbv2',
    config=my_config,
    aws_access_key_id=os.environ['aws_access_key_id'],
    aws_secret_access_key=os.environ['aws_secret_access_key']
)
security_group = client.SecurityGroup('id')
waiter = client.get_waiter('nat_gateway_available')
waiter_ec2 = client.get_waiter('instance_running')
vpc_sidr = str('10.0.0.0/16')
vpc_name = str('my-vpc')
type = str('t2.micro')
ami = str('ami-084e8c05825742534')
key = str('ssh-key-trainee')
instanceName = 'private-one'
user_data = '''
#!/bin/bash

sudo amazon-linux-extras install -y nginx1
sudo systemctl start nginx
'''

subnets = {
    'a-public':
        {'cidr': '10.0.101.0/24', 'zone': "eu-west-2a"},
    'b-public':
        {'cidr': '10.0.102.0/24', 'zone': "eu-west-2b"},
    'a-private':
        {'cidr': '10.0.1.0/24', 'zone': "eu-west-2a"},
    'b-private':
        {'cidr': '10.0.2.0/24', 'zone': "eu-west-2b"}
}

#############################vpc part begin
##### Create vpc

vpc = ec2.create_vpc(
    CidrBlock=vpc_sidr,
    TagSpecifications=[
        {
            'ResourceType': 'vpc',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': vpc_name
                },
            ]
        },
    ]
)
print("Vpc with id" + " " + vpc.id  + " " + "and name" + " " + vpc_name + " " + "was created")
vpc.wait_until_available()

## Create a Subnet
for name, params in subnets.items():
        subnet = client.create_subnet(
            CidrBlock=params.get('cidr'),
            VpcId=vpc.id,
            AvailabilityZone=params.get('zone'),
            TagSpecifications=[
                {
                    'ResourceType': 'subnet',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': vpc_name + "_" + name
                        },
                    ]
                },
            ]
        )
        print("Subnet with id " + subnet['Subnet']["SubnetId"] + " and name " + name + " was added")

# # Create and Attach the Internet Gateway
ig = ec2.create_internet_gateway(
    TagSpecifications=[
        {
            'ResourceType': 'internet-gateway',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': vpc_name + "_" + 'igw'
                },
            ]
        },
    ]
)
print("Internet-gateway with id " + ig.id + " was created")

vpc.attach_internet_gateway(
    InternetGatewayId=ig.id
)
print("Internet-gateway with id" + " " + ig.id  + " " + "was attached to the vpc with id " + vpc.id)

#### get list with subnetIDs
subnets_desc = client.describe_subnets(
    Filters=[
        {
            'Name': 'vpc-id',
            'Values': [
                vpc.id,
            ]
        },
    ],
    DryRun=False,
)

###writing all subnet_ids to separated arrays
subnet_public_ids = []
subnet_private_ids = []
for item in subnets_desc['Subnets']:
    if 'public' in item['Tags'][0]["Value"] and item["VpcId"] == vpc.id:
        subnet_public_ids.append(item["SubnetId"])
    elif 'private' in item['Tags'][0]["Value"] and item["VpcId"] == vpc.id:
        subnet_private_ids.append(item["SubnetId"])

###create nat-gateway
nat = client.allocate_address(
    Domain='vpc',
    DryRun=False,
    TagSpecifications=[
        {
            'ResourceType': 'elastic-ip',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': vpc_name + "_" + "ip"
                },
            ]
        },
    ]
)

eip_nat = client.describe_addresses()
for x in eip_nat['Addresses']:
    if not "AssociationId" in (x):
        Association = (x['AllocationId'])
print("Elastic IP with id " + Association + " was allocated")

nat_gw = client.create_nat_gateway(
    AllocationId=Association,
    DryRun=False,
    SubnetId=subnet_public_ids[0],
    TagSpecifications=[
        {
            'ResourceType': 'natgateway',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value':  vpc_name + "_" + "nat"
                },
            ]
        },
    ],
    ConnectivityType='public',
)
print("Nat-gateway with id " + nat_gw['NatGateway']["NatGatewayId"] + " is creating ...")
print("Please wait till nat-gateway will be available ...")

waiter.wait(
    DryRun=False,
    MaxResults=120,
    NatGatewayIds=[
        nat_gw['NatGateway']["NatGatewayId"],
    ],
    WaiterConfig={
        'Delay': 50,
        'MaxAttempts': 60
    }
)
print("Nat-gateway with id " + nat_gw['NatGateway']["NatGatewayId"] + " was created")

# Create public route table
route_table_public = vpc.create_route_table(
    TagSpecifications=[
        {
            'ResourceType': 'route-table',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': "rtb_" + vpc_name + "_public"
                },
            ]
        },
    ]
)
print("Route table with id " + route_table_public.id + " was created")

####add routes with igw
route = route_table_public.create_route(
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=ig.id,
    RouteTableId=route_table_public.id
)
print("Route [Destination 0.0.0.0/0 to internet-gateway with id" + ig.id + "] to route table with id " + route_table_public.id + "was added")

#associate the route table with the subnet
for subnet in subnet_public_ids:
    route_table_public.associate_with_subnet(
        SubnetId=subnet
    )
    print("Route with id " + route_table_public.id + " table was associated with" + subnet)

# Create private route table
route_table_private = vpc.create_route_table(
    TagSpecifications=[
        {
            'ResourceType': 'route-table',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': "rtb_" + vpc_name + "_private"
                },
            ]
        },
    ]
)
print("Route table with id " + route_table_private.id + " was created")

route = route_table_private.create_route(
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=nat_gw['NatGateway']["NatGatewayId"],
    RouteTableId=route_table_private.id
)
print("Route [Destination 0.0.0.0/0 to nat-gateway with id" + nat_gw['NatGateway']["NatGatewayId"] + "] to route table with id " + route_table_public.id + "was added")

#associate the route table with the subnet
for subnet in subnet_private_ids:
    route_table_private.associate_with_subnet(
        SubnetId=subnet
    )
    print("Route with id " + route_table_private.id + " table was associated with" + subnet)

#############################vpc part end
#############################part with security group begin
#Create a security group and allow SSH inbound rule for bastion
sg_bastion = ec2.create_security_group(
    GroupName='bastion',
    Description='only allow SSH traffic',
    VpcId=vpc.id,
    TagSpecifications=[
        {
            'ResourceType': 'security-group',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'bastion'
                },
            ]
        },
    ],
)
print("Security group for bastion with id " + sg_bastion.id + " was added")

data = security_group.authorize_ingress(
    GroupId=sg_bastion.id,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [
                {
                    'CidrIp': '0.0.0.0/0',
                    'Description': 'rule for access over ssh'
                }
        ],
        }
    ],
    TagSpecifications=[
        {
            'ResourceType': 'security-group-rule',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'ssh for bastion'
                },
            ]
        },
    ]
)
print("Security Group Created with id " + sg_bastion.id + " was added")

### add security group for public load balancer
sg_public = ec2.create_security_group(
    GroupName='public',
    Description='only allow HTTP traffic',
    VpcId=vpc.id,
    TagSpecifications=[
        {
            'ResourceType': 'security-group',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'HTTP_public'
                },
            ]
        },
    ],
)
print("Security group for public load balancer with id " + sg_public.id + " was added")

data = security_group.authorize_ingress(
    GroupId=sg_public.id,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'IpRanges': [
                {
                    'CidrIp': '0.0.0.0/0',
                    'Description': 'rule for HTTP'
                }
        ],
        }
    ],
    TagSpecifications=[
        {
            'ResourceType': 'security-group-rule',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'HTTP for public LB'
                },
            ]
        },
    ]
)
print("Security Group Created with id " + sg_public.id + " was added")

### add security group for public load balancer
sg_private = ec2.create_security_group(
    GroupName='private',
    Description='only allow HTTP traffic',
    VpcId=vpc.id,
    TagSpecifications=[
        {
            'ResourceType': 'security-group',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'HTTP_private'
                },
            ]
        },
    ],
)
print("Security group for public load balancer with id " + sg_private.id + " was added")

data = security_group.authorize_ingress(
    GroupId=sg_private.id,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'IpRanges': [
                {
                    'CidrIp': subnets["a-public"]["cidr"],
                    'Description': 'rule for HTTP'
                },
                {
                    'CidrIp': subnets["b-public"]["cidr"],
                    'Description': 'rule for HTTP'
                },
                {
                    'CidrIp': subnets["a-private"]["cidr"],
                    'Description': 'rule for HTTP'
                },
                {
                    'CidrIp': subnets["b-private"]["cidr"],
                    'Description': 'rule for HTTP'
                }
        ],
        }
    ],
    TagSpecifications=[
        {
            'ResourceType': 'security-group-rule',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'HTTP for private LB'
                },
            ]
        },
    ]
)
print("Security Group Created with id " + sg_private.id + " was added")
###Add nested rules for load balancers
nested = ec2.create_security_group(
    GroupName='nested',
    Description='nested',
    VpcId=vpc.id,
    TagSpecifications=[
        {
            'ResourceType': 'security-group',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'nested'
                },
            ]
        },
    ],
)
print("Nested Security group with id " + nested.id + " was added")

data = security_group.authorize_ingress(
    GroupId=nested.id,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'UserIdGroupPairs': [
                {
                    'Description': 'rules for public lb',
                    'GroupId': sg_public.id,
                    'VpcId': vpc.id,
                },
                {
                    'Description': 'rules for private lb',
                    'GroupId': sg_private.id,
                    'VpcId': vpc.id,
                },
            ]
        }
    ],
    TagSpecifications=[
        {
            'ResourceType': 'security-group-rule',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'nested'
                },
            ]
        },
    ]
)
print("Rules for Nested Security Group was added")

#############################part with security group ended
#######Create instances
ec2_private_one = ec2.create_instances(
    InstanceType=type,
    ImageId=ami,
    KeyName=key,
    SubnetId=subnet_private_ids[0],
    BlockDeviceMappings=[
        {
            'DeviceName': '/dev/xvda',
            'Ebs': {
                'VolumeSize': 8,
                'VolumeType': 'gp2',
                'DeleteOnTermination': True
            }
        },
    ],
    SecurityGroupIds=[
        sg_private.id,
    ],
    UserData=user_data,
    MinCount=1,
    MaxCount=1,
    TagSpecifications = [
        {
            'ResourceType': 'instance',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': instanceName
                },
            ]
        }
    ]
)

ec2_private_one_desc = client.describe_instances(
    Filters = [
        {
            'Name': 'instance-state-name',
            'Values': [
                'running',
                'pending'
            ]
        },
        {
            'Name': 'tag:Name',
            'Values': [
                instanceName
            ]
        }
    ]
)

waiter_ec2.wait(
    InstanceIds=[
        ec2_private_one_desc["Reservations"][0]['Instances'][0]['InstanceId'],
    ],
    DryRun=False,
    WaiterConfig={
        'Delay': 30,
        'MaxAttempts': 60
    }
)
print("Instance with id " + ec2_private_one_desc["Reservations"][0]['Instances'][0]['InstanceId'] + " was added")

ec2_bastion = ec2.create_instances(
    InstanceType=type,
    ImageId=ami,
    KeyName=key,
    BlockDeviceMappings=[
        {
            'DeviceName': '/dev/xvda',
            'Ebs': {
                'VolumeSize': 8,
                'VolumeType': 'gp2',
                'DeleteOnTermination': True
            }
        },
    ],
    NetworkInterfaces=[
        {
            'DeviceIndex': 0,
            'SubnetId': subnet_public_ids[0],
            'AssociatePublicIpAddress': True,
            'Groups': [ sg_bastion.id ]
        },
    ],
    MinCount=1,
    MaxCount=1,
    TagSpecifications = [
        {
            'ResourceType': 'instance',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'bastion'
                },
            ]
        }
    ]
)
ec2_bastion_desc = client.describe_instances(
    Filters = [
        {
            'Name': 'instance-state-name',
            'Values': [
                'running',
                'pending'
            ]
        },
        {
            'Name': 'tag:Name',
            'Values': [
                'bastion'
            ]
        }
    ]
)
print("Bastion with id " + ec2_bastion_desc["Reservations"][0]['Instances'][0]['InstanceId'] + " was added")

#######part for balancers
###add public one start
lb_public = client_elb.create_load_balancer(
    Name="mylb-public",
    Subnets=[
        subnet_public_ids[0],
        subnet_public_ids[1]
    ],
    SecurityGroups=[
        sg_public.id,
    ],
    Tags=[
        {
            'Key': 'Name',
            'Value': 'mylb-public'
        },
    ],
    Type='application',
    IpAddressType='ipv4',
    Scheme='internet-facing'
)
print("Load balancer with arn " + lb_public["LoadBalancers"][0]["LoadBalancerArn"] + " was added")

lb_tg = client_elb.create_target_group(
    Name='public',
    Protocol='HTTP',
    Port=80,
    VpcId=vpc.id,
    HealthCheckProtocol='HTTP',
    HealthCheckPort='80',
    HealthCheckPath='/',
    Matcher={
        'HttpCode': '200'
    },
    TargetType='instance'
)
print("Target group with id " + lb_tg["TargetGroups"][0]["TargetGroupArn"] + " was added")

register_targets = client_elb.register_targets(
    TargetGroupArn=lb_tg["TargetGroups"][0]["TargetGroupArn"],
    Targets=[
        {
            'Id': ec2_private_one_desc["Reservations"][0]['Instances'][0]['InstanceId'],
            'Port': 80,
        },
    ]
)
print("Instanse with ID " + ec2_private_one_desc["Reservations"][0]['Instances'][0]['InstanceId'] + " was added to target group")

listener_public = client_elb.create_listener(
    DefaultActions=[
        {
            'TargetGroupArn': lb_tg["TargetGroups"][0]["TargetGroupArn"],
            'Type': 'forward',
        },
    ],
    LoadBalancerArn=lb_public["LoadBalancers"][0]["LoadBalancerArn"],
    Port=80,
    Protocol='HTTP',
)
print("HTTP listener was added to load balancer")
###add public one end

###add private one start
lb_private = client_elb.create_load_balancer(
    Name="mylb-private",
    Subnets=[
        subnet_private_ids[0],
        subnet_private_ids[1]
    ],
    SecurityGroups=[
        sg_private.id,
    ],
    Tags=[
        {
            'Key': 'Name',
            'Value': 'mylb-private'
        },
    ],
    Type='application',
    IpAddressType='ipv4',
    Scheme='internal'
)
print("Load balancer with arn " + lb_private["LoadBalancers"][0]["LoadBalancerArn"] + " was added")

lb_tg_private = client_elb.create_target_group(
    Name='private',
    Protocol='HTTP',
    Port=80,
    VpcId=vpc.id,
    HealthCheckProtocol='HTTP',
    HealthCheckPort='80',
    HealthCheckPath='/',
    Matcher={
        'HttpCode': '200'
    },
    TargetType='instance'
)
print("Target group with arn " + lb_tg_private["TargetGroups"][0]["TargetGroupArn"] + " was added")

register_targets_private = client_elb.register_targets(
    TargetGroupArn=lb_tg_private["TargetGroups"][0]["TargetGroupArn"],
    Targets=[
        {
            'Id': ec2_private_one_desc["Reservations"][0]['Instances'][0]['InstanceId'],
            'Port': 80,
        },
    ]
)
print("Instance with ID " + ec2_private_one_desc["Reservations"][0]['Instances'][0]['InstanceId'] + " was added to target group")

listener_private = client_elb.create_listener(
    DefaultActions=[
        {
            'TargetGroupArn': lb_tg_private["TargetGroups"][0]["TargetGroupArn"],
            'Type': 'forward',
        },
    ],
    LoadBalancerArn=lb_private["LoadBalancers"][0]["LoadBalancerArn"],
    Port=80,
    Protocol='HTTP',
)
print("HTTP listener was added to private load balancer")
###add private one end