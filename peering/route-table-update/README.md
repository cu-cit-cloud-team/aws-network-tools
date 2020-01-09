# DRAFT - PROOF OF CONCEPT - DRAFT

# Using Terraform to Add Routes to Peered VPC

This Terraform solution makes it easy to add routes to existing Route Tables in order to utilize an established peering connection in the "acceptor" VPC. The "acceptor" VPC is the one that accepts the peering connection offered by the "requestor" VPC.

The steps to use this would be:
1. Requestor VPC creates the Peering Connection Request (by any means you wish)
1. Acceptor VPC accepts the offered Peering Connection (by any means you wish)
1. Use the Terraform tool in this repo to add routes for all route tables in the "acceptor" VPC to utilize the new peering connection.

## Prerequisites

- Docker and Docker-Compos) installed

## How To Use this Terraform Tool

1. Clone this repo
1. `cd ct-aws-network-tools/peering/route-table-update`
1. Edit `terraform.tfvars` with the values of the VPCs and CIDR blocks for your situation.
1. `docker-compose build` -- build a Docker image to use for execution
1. `./go.sh` -- starts a container where Terraform is available, and drops you into a shell in that container.
1. Setup AWS CLI credentials that will be valid for the AWS account that contains the "acceptor" VPC.
5. `terraform init`
6. `terraform plan` -- review the changes to be made
7. `terraform apply` -- answer `yes` when asked whether the changes are OK to apply
8. `exit` out of the container
9. `docker-compose down` -- stop the container

## Notes

If any of the route tables in the "acceptor" VPC already contain routes for the "requestor" VPC CIDR, then you will get an error message similar to this:
```
Error: Error creating route: RouteAlreadyExists: The route identified by 172.31.0.0/16 already exists.
        status code: 400, request id: c636a8c8-eb19-4bf5-8fcd-27f5dba8b3c3

  on routes-to-use-peer.tf line 68, in resource "aws_route" "peer_route":
  68: resource "aws_route" "peer_route" {
```

## Cleanup

Here, Terraform is used as a transient (fire-and-forget) tool, so we don't care about the state file it created. You don't need to save any of the files or directories created by Terraform. Nor do you need to save the `terraformt.fvars` file.