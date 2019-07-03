#!/usr/bin/env python3
"""
Show AWS network resources in play for a source, and analyze whether
there any obvious problems for reaching a destination
"""
import sys
from pprint import pprint
import argparse
import ipaddress
import socket
import boto3

# CIDR block describing all IPV addresses
ALL_IPV4 = '0.0.0.0/0'

def get_value_for_tag_key(tags, key):
    """
    Get the value for tag with provided key

    Parameters:
        tags (list of dictionary): list of Key/Value pairs

            Example tags:
            [{'Key': 'PrincipalId', 'Value': 'AROAJY62KZGVJNG45AAZE:AutoScaling'},
             {'Key': 'Name', 'Value': 'ecs-cs-jenkins-instance'},
             {'Key': 'aws:autoscaling:groupName', 'Value': 'ecs-cs-jenkins'},
             {'Key': 'Application', 'Value': 'Jenkins'}]

        key (string): the key to return the value for

    Returns:
        string

        Example:
    """
    for item in tags:
        if item.get('Key', '') == key:
            return item.get('Value', '')
    return ''

def find_subnet_for_ip(client, subnet_id_list, ip_address_str, verbose=False):
    response = client.describe_subnets(
        SubnetIds=subnet_id_list
    )
    if verbose:
        print("Subnets:")
        pprint(response['Subnets'])
    ip_address = ipaddress.ip_address(ip_address_str)
    for s in response['Subnets']:
        cidr = ipaddress.ip_network(s['CidrBlock'])
        if ip_address in cidr:
            return s, response['Subnets']
    return None, response['Subnets']

def find_route_matches(routes, dest_ip_str):
    dest_ip = ipaddress.ip_address(dest_ip_str)
    for r in routes:
        route_cidr = ipaddress.ip_network(r['DestinationCidrBlock'])
        if dest_ip in route_cidr:
            return r
    return None

def find_nacl_rule_matches(nacl_entries, dest_ip_str):
    inbound_rules = []
    outbound_rules = []
    dest_ip = ipaddress.ip_address(dest_ip_str)
    for e in nacl_entries:
        cidr = ipaddress.ip_network(e['CidrBlock'])
        if dest_ip in cidr:
            if e['Egress']:
                outbound_rules.append(e)
            else:
                inbound_rules.append(e)
    return inbound_rules, outbound_rules

def find_security_group_matches(permissions, dest_ip_str):
    matches = []
    dest_ip = ipaddress.ip_address(dest_ip_str)
    for p in permissions:
        matched_p = None
        if len(p['IpRanges']) > 0:
            for r in p['IpRanges']:
                if r['CidrIp'] == ALL_IPV4:
                    matched_p = p
                    break
                cidr = ipaddress.ip_network(r['CidrIp'])
                if dest_ip in cidr:
                    matched_p = p
                    break
        if len(p['Ipv6Ranges']) > 0:
            print("WARNING. Ignoring IPv6 rules in Security Group.")
        if len(p['PrefixListIds']) > 0:
            print("WARNING. Ignoring Perfix List rules in Security Group.")
        if len(p['UserIdGroupPairs']) > 0:
            matched_p = p
        if matched_p is not None:
            matches.append(matched_p)
    return matches

def get_nacls_for_subnets(client, list_subnet_ids, verbose=False):
    response = client.describe_network_acls(
        Filters=[
            {
                'Name': 'association.subnet-id',
                'Values': list_subnet_ids
            }
        ]
    )
    if verbose:
        pprint(response['NetworkAcls'])
    return response['NetworkAcls']

def get_route_tables_for_subnets(client, list_subnet_ids, verbose=False):
    response = client.describe_route_tables(
        Filters=[
            {
                'Name': 'association.subnet-id',
                'Values': list_subnet_ids
            },
        ]
    )
    if verbose:
        pprint(response['RouteTables'])
    return response['RouteTables']

def get_nat_gateway(client, nat_gateway_id):
    response = client.describe_nat_gateways(
        NatGatewayIds=[nat_gateway_id]
    )
    assert len(response['NatGateways']) == 1
    return response['NatGateways'][0]

def get_vpc_peering_connections(client, peering_connection_id):
    response = client.describe_vpc_peering_connections(
        VpcPeeringConnectionIds=[peering_connection_id]
    )
    assert len(response['VpcPeeringConnections']) == 1
    return response['VpcPeeringConnections'][0]


def get_ec2_instance_by_private_ip(client, private_ip_address):
    """
    Retrieve security group rules that are relevant to a destination ip address

    Parameters:
        client: boto3 EC2 client
        private_ip_address (string): private ip address of the EC2 instance

    Returns:
        dictionary

        Example:

        {'AmiLaunchIndex': 0,
        'Architecture': 'x86_64',
        'BlockDeviceMappings': [{'DeviceName': '/dev/xvda',
                              'Ebs': {'AttachTime': datetime.datetime(2018, 12, 3, 11, 47, 22, tzinfo=tzutc()),
                                      'DeleteOnTermination': True,
                                      'Status': 'attached',
                                      'VolumeId': 'vol-007bf0f0e77897c77'}},
                             {'DeviceName': '/dev/xvdcz',
                              'Ebs': {'AttachTime': datetime.datetime(2018, 12, 3, 11, 47, 22, tzinfo=tzutc()),
                                      'DeleteOnTermination': True,
                                      'Status': 'attached',
                                      'VolumeId': 'vol-06b0b622fbf711aac'}}],
        'CapacityReservationSpecification': {'CapacityReservationPreference': 'open'},
        'ClientToken': '2aa59dcf-938a-0597-6859-687e6d06e85d_subnet-dd8519f6_1',
        'CpuOptions': {'CoreCount': 2, 'ThreadsPerCore': 1},
        'EbsOptimized': False,
        'EnaSupport': True,
        'HibernationOptions': {'Configured': False},
        'Hypervisor': 'xen',
        'IamInstanceProfile': {'Arn': 'arn:aws:iam::123456789012:instance-profile/cs-jenkins-instance-profile',
                            'Id': 'AIPAII72YLWTTYY35SULY'},
        'ImageId': 'ami-aff65ad2',
        'InstanceId': 'i-0cd2fc1a3d56dab3f',
        'InstanceType': 't2.medium',
        'KeyName': 'cu-conf',
        'LaunchTime': datetime.datetime(2018, 12, 3, 11, 47, 21, tzinfo=tzutc()),
        'Monitoring': {'State': 'enabled'},
        'NetworkInterfaces': [{'Attachment': {'AttachTime': datetime.datetime(2018, 12, 3, 11, 47, 21, tzinfo=tzutc()),
                                          'AttachmentId': 'eni-attach-04aa01e0141b5bdcd',
                                          'DeleteOnTermination': True,
                                          'DeviceIndex': 0,
                                          'Status': 'attached'},
                            'Description': '',
                            'Groups': [{'GroupId': 'sg-d76e6da2',
                                        'GroupName': 'cs-jenkins'},
                                      {'GroupId': 'sg-b36d6ec6',
                                        'GroupName': 'cs-jenkins-ec2'}],
                            'Ipv6Addresses': [],
                            'MacAddress': '12:bf:c9:57:3b:2e',
                            'NetworkInterfaceId': 'eni-085b4dc0e79db396c',
                            'OwnerId': '123456789012',
                            'PrivateDnsName': 'ip-10-92-77-247.ec2.internal',
                            'PrivateIpAddress': '10.92.77.247',
                            'PrivateIpAddresses': [{'Primary': True,
                                                    'PrivateDnsName': 'ip-10-92-77-247.ec2.internal',
                                                    'PrivateIpAddress': '10.92.77.247'}],
                            'SourceDestCheck': True,
                            'Status': 'in-use',
                            'SubnetId': 'subnet-dd8519f6',
                            'VpcId': 'vpc-71070114'}],
        'Placement': {'AvailabilityZone': 'us-east-1c',
                  'GroupName': '',
                  'Tenancy': 'default'},
        'PrivateDnsName': 'ip-10-92-77-247.ec2.internal',
        'PrivateIpAddress': '10.92.77.247',
        'ProductCodes': [],
        'PublicDnsName': '',
        'RootDeviceName': '/dev/xvda',
        'RootDeviceType': 'ebs',
        'SecurityGroups': [{'GroupId': 'sg-d76e6da2', 'GroupName': 'cs-jenkins'},
                        {'GroupId': 'sg-b36d6ec6', 'GroupName': 'cs-jenkins-ec2'}],
        'SourceDestCheck': True,
        'State': {'Code': 16, 'Name': 'running'},
        'StateTransitionReason': '',
        'SubnetId': 'subnet-dd8519f6',
        'Tags': [{'Key': 'PrincipalId', 'Value': 'AROAJY62KZGVJNG45AAZE:AutoScaling'},
              {'Key': 'Terraform', 'Value': 'true'},
              {'Key': 'Inspector Group', 'Value': 'default'},
              {'Key': 'Patch Group', 'Value': 'cu-cit-cloud-team-patching'},
              {'Key': 'Creator', 'Value': 'AutoScaling'},
              {'Key': 'lifecycle-policy', 'Value': 'none'},
              {'Key': 'Environment', 'Value': 'development'},
              {'Key': 'Maintenance Group', 'Value': 'immuteable'},
              {'Key': 'Name', 'Value': 'ecs-cs-jenkins-instance'},
              {'Key': 'aws:autoscaling:groupName', 'Value': 'ecs-cs-jenkins'},
              {'Key': 'Application', 'Value': 'Jenkins'}],
        'VirtualizationType': 'hvm',
        'VpcId': 'vpc-71070114'}
    """
    response = client.describe_instances(
        Filters=[
            {
                'Name': 'private-ip-address',
                'Values': [private_ip_address]
            }
        ]
    )
    if len(response['Reservations']) < 1:
        return None
    assert len(response['Reservations']) == 1
    assert len(response['Reservations'][0]['Instances']) == 1
    source_instance = response['Reservations'][0]['Instances'][0]
    source_instance['Name'] = get_value_for_tag_key(source_instance['Tags'], 'Name')
    return source_instance

def get_security_groups(client, sg_group_ids, dest_ip_address, verbose=False):
    """
    Retrive security group rules that are relevant to a destination ip address

    Parameters:
        client: boto3 EC2 client
        sg_group_ids (list of string): list of security group IDs
        dest_ip_address (string): private or public ip address of the destination
        verbose (boolean): print extra info; default is False

    Returns:
        ingress_sg_matches: matching rules from ingress security groups
        egress_sg_matches: matching rules from egress security groups
    """
    response = client.describe_security_groups(
        GroupIds=sg_group_ids
    )
    assert len(response['SecurityGroups']) == len(sg_group_ids)
    source_security_groups = response['SecurityGroups']

    if verbose:
        pprint(source_security_groups)

    ingress_sg_matches = []
    egress_sg_matches = []
    for security_group in source_security_groups:
        temp = find_security_group_matches(security_group['IpPermissions'], dest_ip_address)
        ingress_sg_matches += temp
        temp = find_security_group_matches(security_group['IpPermissionsEgress'], dest_ip_address)
        egress_sg_matches += temp
    return ingress_sg_matches, egress_sg_matches

def get_rds_instance(client, source_rds_name, verbose=False):
    """
    Retrive info about an RDS instance

    Parameters:
        client: boto3 RDS client
        source_rds_name (string): name of the RDS instance (e.g., boomidev)
        verbose (boolean): print extra info; default is False

    Returns:
        dictionary: RDS instance properties; example below

        {'AllocatedStorage': 30,
         'AssociatedRoles': [],
         'AutoMinorVersionUpgrade': True,
         'AvailabilityZone': 'us-east-1d',
         'BackupRetentionPeriod': 14,
         'CACertificateIdentifier': 'rds-ca-2015',
         'CopyTagsToSnapshot': True,
         'DBClusterIdentifier': 'billing-detail-cluster',
         'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:billing-detail',
         'DBInstanceClass': 'db.t2.medium',
         'DBInstanceIdentifier': 'billing-detail',
         'DBInstanceStatus': 'available',
         'DBName': 'billing_detail',
         'DBParameterGroups': [{'DBParameterGroupName': 'default.aurora5.6',
                                'ParameterApplyStatus': 'in-sync'}],
         'DBSecurityGroups': [],
         'DBSubnetGroup': {'DBSubnetGroupDescription': 'Created from the RDS '
                                                      'Management Console',
                          'DBSubnetGroupName': 'default-vpc-71070114',
                          'SubnetGroupStatus': 'Complete',
                          'Subnets': [{'SubnetAvailabilityZone': {'Name': 'us-east-1c'},
                                        'SubnetIdentifier': 'subnet-dd8519f6',
                                        'SubnetStatus': 'Active'},
                                      {'SubnetAvailabilityZone': {'Name': 'us-east-1d'},
                                        'SubnetIdentifier': 'subnet-8d95c4fa',
                                        'SubnetStatus': 'Active'}],
                          'VpcId': 'vpc-71070114'},
         'DbInstancePort': 0,
         'DbiResourceId': 'db-5P52ZHU3GJAYBTC5DNY6N2GS5U',
         'DeletionProtection': False,
         'DomainMemberships': [],
         'Endpoint': {'Address': 'billing-detail.cup2kudlch8b.us-east-1.rds.amazonaws.com',
                      'HostedZoneId': 'Z2R2ITUGPM61AM',
                      'Port': 3306},
         'Engine': 'aurora',
         'EngineVersion': '5.6.10a',
         'IAMDatabaseAuthenticationEnabled': False,
         'InstanceCreateTime': datetime.datetime(2016, 8, 5, 3, 28, 59, 490000, tzinfo=tzutc()),
         'LicenseModel': 'general-public-license',
         'MasterUsername': 'root',
         'MonitoringInterval': 0,
         'MultiAZ': False,
         'OptionGroupMemberships': [{'OptionGroupName': 'default:aurora-5-6',
                                     'Status': 'in-sync'}],
         'PendingModifiedValues': {},
         'PreferredBackupWindow': '08:46-09:16',
         'PreferredMaintenanceWindow': 'mon:04:41-mon:05:11',
         'PromotionTier': 1,
         'PubliclyAccessible': False,
         'ReadReplicaDBInstanceIdentifiers': [],
         'StorageEncrypted': False,
         'StorageType': 'aurora',
         'VpcSecurityGroups': [{'Status': 'active',
                                'VpcSecurityGroupId': 'sg-b8348ec1'}]}
    """
    response = client.describe_db_instances(
        DBInstanceIdentifier=source_rds_name
    )
    if verbose:
        pprint(response)
    assert len(response['DBInstances']) <= 1
    if  len(response['DBInstances']) == 0:
        return None
    return response['DBInstances'][0]

def report_nacl(source_nacl, source_ip_address, dest_ip_address, verbose=False):
    """
    Analyze and report on the NACL

    Parameters:
        source_nacl (dict): NACL properties from describe_network_acls() for the NACL that rules the source
        source_ip_address (string): private ip address of the source
        dest_ip_address (string): private or public ip address of the destination
        verbose (boolean): print extra info; default is False

    Returns:
        boolean: whether or not a network problem exists in from the perspective of the NACL
    """
    network_problem_exists = False
    print("============================================================")
    print("Network ACL analysis")
    print("NACL entries applied on source IP " + source_ip_address + " relevant to destination IP " + dest_ip_address)
    inbound_rules, outbound_rules = find_nacl_rule_matches(source_nacl['Entries'], dest_ip_address)
    print("Inbound Rules:")
    pprint(inbound_rules)
    if len(inbound_rules) == 0:
        print("NETWORK CONNECTIVITY ERROR. No relevant inbound rules for NACL.")
        network_problem_exists = True
    print("Outbound Rules:")
    pprint(outbound_rules)
    if len(outbound_rules) == 0:
        print("NETWORK CONNECTIVITY ERROR. No relevant outbound rules for NACL.")
        network_problem_exists = True
    return network_problem_exists

def report_route_table(ec2_client, source_route_table, source_vpc_id, source_ip_address, dest_ip_address, verbose=False):
    network_problem_exists = False
    print("============================================================")
    print("Analysis of Route Table applied on source IP " + source_ip_address + " relevant to destination IP " + dest_ip_address)
    print("Route Table in use for source: " + source_route_table['RouteTableId'])
    if verbose:
        pprint(source_route_table)
    print("Finding route to " + dest_ip_address)
    r = find_route_matches(source_route_table['Routes'], dest_ip_address)
    if r is not None:
        print("Matching route:")
        pprint(r)

    if r is None:
        print("NETWORK CONNECTIVITY ERROR. There is no route to " + dest_ip_address)
        network_problem_exists = True

    elif 'GatewayId' in r:
        # uses a VGW
        print("Via virtual gateway: " + r['GatewayId'])

    elif 'NatGatewayId' in r:
        # NAT
        print("Via NAT: " + r['NatGatewayId'])
        nat_gateway = get_nat_gateway(ec2_client, r['NatGatewayId'])
        if verbose:
            pprint(nat_gateway)
        print("NAT Gateway state: " + nat_gateway['State'])
        if nat_gateway['State'] != 'available':
            print("NETWORK CONNECTIVITY ERROR. NAT Gateway not available")
            network_problem_exists = True

    elif 'VpcPeeringConnectionId' in r:
        # peering connection
        print("Via peering connection: " + r['VpcPeeringConnectionId'])

        vpc_peering_connection = get_vpc_peering_connections(ec2_client, r['VpcPeeringConnectionId'])
        if verbose:
            pprint(vpc_peering_connection)
        print("VPC Peering Connection status: " + vpc_peering_connection['Status']['Code'])
        if vpc_peering_connection['Status']['Code'] != 'active':
            print("NETWORK CONNECTIVITY ERROR. VPC Peering Connection is not active")
            network_problem_exists = True

        if vpc_peering_connection['AccepterVpcInfo']['VpcId'] == source_vpc_id:
            # Destiantion VPC is RequestorVpcInfo
            destination_peering_info = vpc_peering_connection['RequesterVpcInfo']
        else:
            destination_peering_info = vpc_peering_connection['AccepterVpcInfo']
        print("Destination peering info:")
        pprint(destination_peering_info)

    else:
        print("ERROR. Unknown route type:")
        pprint(r)
        network_problem_exists = True

    return network_problem_exists

def report_security_groups(ec2_client, source_security_group_ids, source_ip_address, dest_ip_address, verbose=False):
    network_problem_exists = False
    ingress_sg_matches, egress_sg_matches = get_security_groups(ec2_client, source_security_group_ids, dest_ip_address, verbose=verbose)

    print("============================================================")
    print("Analysis of Security Group ingress/egress applied on source IP " + source_ip_address + " to/from destination IP " + dest_ip_address)
    print("Potential Ingress Matches")
    pprint(ingress_sg_matches)
    if len(ingress_sg_matches) == 0:
        network_problem_exists = True
        print("NETWORK CONNECTIVITY ERROR. No ingress is allowed by source Security Groups for " + dest_ip_address)
        print("\tPerhaps access to this AWS resource indirect, through a loadbalancer? ")

    print("Potential Egress Matches:")
    pprint(egress_sg_matches)
    if len(egress_sg_matches) == 0:
        network_problem_exists = True
        print("NETWORK CONNECTIVITY ERROR. No egress is allowed by source Security Groups for " + dest_ip_address)
        print("\tPerhaps access to this AWS resource indirect, through a loadbalancer? ")
    return network_problem_exists

def report_db_subnet_groups(ec2_client, subnet_id_list, verbose=False):
    # validate that DBSubnet Group subnets use the same RouteTable
    result = get_route_tables_for_subnets(ec2_client, subnet_id_list, verbose=verbose)
    assert len(result) > 0
    if len(result) > 1:
        print("WARNING. Subnets in DBSubnetGroup do not use the same route table!")

    result = get_nacls_for_subnets(ec2_client, subnet_id_list, verbose=verbose)
    assert len(result) > 0
    if len(result) > 1:
        print("WARNING. Subnets in DBSubnetGroup do not use the same NACL!")
    return False

def main(argv):

    parser = parser = argparse.ArgumentParser(description='show network connectivity between two IPs')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help="show more info")
    parser.add_argument('-s', '--source-ec2-ip', required=False, default='', help="private IP address of source in AWS")
    parser.add_argument('-d', '--dest-ip', required=True, help="destination IP address")
    parser.add_argument('-r', '--source-rds', required=False, default='', help="name of RDS instance for source")
    args = parser.parse_args()

    verbose = args.verbose
    source_ec2_ip_address = args.source_ec2_ip
    dest_ip_address = args.dest_ip
    source_rds_name = args.source_rds
    source_security_group_ids = []

    print("============================================================")
    print("Input parameters:")
    print("verbose: " + str(verbose))
    print("source_ec2_ip_address: " + source_ec2_ip_address)
    print("dest_ip_address: " + dest_ip_address)
    print("source_rds_name: " + source_rds_name)

    network_problem_exists = False
    ec2_client = boto3.client('ec2')
    rds_client = boto3.client('rds')

    print("============================================================")
    print("Source info:")

    if source_ec2_ip_address != '':
        source_instance = get_ec2_instance_by_private_ip(ec2_client, source_ec2_ip_address)
        if source_instance is None:
            print("ERROR. Source EC2 instance with private IP address " + source_ec2_ip_address + " cannot be found.")
        else:
            # EC2
            source_vpc_id = source_instance['VpcId']
            source_subnet_id = source_instance['SubnetId']
            source_name = source_instance['Name']
            source_dns_name = source_instance['PrivateDnsName']
            source_ip_address = source_instance['PrivateIpAddress']
            assert source_ec2_ip_address == source_ip_address

            source_security_groups = source_instance['SecurityGroups']
            for sg in source_security_groups:
                source_security_group_ids.append(sg['GroupId'])

            if verbose:
                pprint(source_instance)
            print("InstanceId: " + source_instance['InstanceId'])

    if source_rds_name != '':
        source_rds_instance = get_rds_instance(rds_client, source_rds_name, verbose=verbose)
        if source_rds_instance is None:
            print("ERROR. Source RDS instance with name " + source_rds_name + " cannot be found.")
        else:
            # RDS
            source_name = source_rds_instance['DBInstanceIdentifier']
            source_vpc_id = source_rds_instance['DBSubnetGroup']['VpcId']
            source_dns_name = source_rds_instance['Endpoint']['Address']
            source_ip_address = socket.gethostbyname(source_dns_name)

            subnet_id_list = []
            for s in source_rds_instance['DBSubnetGroup']['Subnets']:
                if s['SubnetStatus'] == 'Active':
                    subnet_id_list.append(s['SubnetIdentifier'])
                else:
                    print("WARNING. Subnet " + s['SubnetIdentifier'] + " in DBSubnetGroup is not 'Active'")

            source_subnet, all_subnets = find_subnet_for_ip(ec2_client, subnet_id_list, source_ip_address, verbose=verbose)
            assert source_subnet is not None
            source_subnet_id = source_subnet['SubnetId']

            # validate that DBSubnet Group subnets use the same RouteTable
            problem = report_db_subnet_groups(ec2_client, subnet_id_list, verbose=verbose)
            network_problem_exists = network_problem_exists or problem

            source_security_groups = source_rds_instance['VpcSecurityGroups']
            for sg in source_security_groups:
                source_security_group_ids.append(sg['VpcSecurityGroupId'])

            print("RDS Instance PubliclyAccessible: " + str(source_rds_instance['PubliclyAccessible']))
            if verbose:
                pprint(source_rds_instance)
            if source_rds_instance['PubliclyAccessible'] and dest_ip_address.starts_with("10."):
                print("WARNING. Destination IP is private, but RDS instance is Public! Results of this analsysi may be incorrect!")

    # EC2 + RDS common values
    print("Source IP Address: " + source_ip_address)
    print("Name: " + source_name)
    print("DNS Name:" + source_dns_name)
    print("SubnetId: " + source_subnet_id)
    print("VpcId: " + source_vpc_id)

    # SECURITY GROUPS
    print("Security Groups: ")
    pprint(source_security_groups)
    problem = report_security_groups(ec2_client, source_security_group_ids, source_ip_address, dest_ip_address, verbose=verbose)
    network_problem_exists = network_problem_exists or problem

    # ROUTE TABLE
    result = get_route_tables_for_subnets(ec2_client, [source_subnet_id], verbose=verbose)
    assert len(result) == 1
    source_route_table = result[0]
    problem = report_route_table(ec2_client, source_vpc_id, source_route_table, source_ip_address, dest_ip_address, verbose=verbose)
    network_problem_exists = network_problem_exists or problem

    # NACL
    result = get_nacls_for_subnets(ec2_client, [source_subnet_id], verbose=verbose)
    assert len(result) == 1
    source_nacl = result[0]
    if verbose:
        pprint(source_nacl)
    problem = report_nacl(source_nacl, source_ip_address, dest_ip_address, verbose)
    network_problem_exists = network_problem_exists or problem

    print("============================================================")
    print("Summary: ")
    if network_problem_exists:
        print("ERROR. Some network connectivity problem exists. Review output of this tool.")
    else:
        print("OK. No obvious network connectivity problem exists from the perspective of the source.")
    print("============================================================")

if __name__ == "__main__":
    main(sys.argv[1:])
