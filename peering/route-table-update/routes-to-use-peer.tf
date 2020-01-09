############################################
# Basic TF config
############################################
terraform {
  required_version = "0.12.19"
}

provider "aws" {
  region  = "us-east-1"
  version = "~> 2.43"
}

############################################
# Variables
############################################

# Requestor is the VPC that initiates the Peering Connection
variable "requestor_vpc_id" {
  type = string
}
variable "requestor_vpc_cidr" {
  type = string
}
variable "requestor_region" {
  type = string
  default = "us-east-1"
}

# Acceptor is the VPC that accepts the Peering Connection
variable "acceptor_vpc_id" {
  type = string
}

variable "acceptor_vpc_cidr" {
  type = string
}

variable "acceptor_region" {
  type = string
  default = "us-east-1"
}

############################################
# Data resources. These resources should
# already exist.
############################################

data "aws_vpc_peering_connection" "peer" {
    vpc_id          = var.requestor_vpc_id
    cidr_block      = var.requestor_vpc_cidr
    region          = var.requestor_region
    
    peer_vpc_id     = var.acceptor_vpc_id
    peer_cidr_block = var.acceptor_vpc_cidr
    peer_region     = var.acceptor_region
    
    status          = "active"
}

data "aws_route_tables" "acceptor_rts" {
  vpc_id = data.aws_vpc_peering_connection.peer.peer_vpc_id
}

############################################
# These routes being added to existing route 
# tables are the main resources we are creating.
############################################
resource "aws_route" "peer_route" {
  for_each = data.aws_route_tables.acceptor_rts.ids
  route_table_id            = each.value
  destination_cidr_block    = data.aws_vpc_peering_connection.peer.cidr_block
  vpc_peering_connection_id = data.aws_vpc_peering_connection.peer.id
}
