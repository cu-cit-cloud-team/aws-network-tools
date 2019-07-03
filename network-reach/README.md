# network-reach (ct-aws-network-tools)

Analyze network connectivity between a source in AWS to some destination

## Arguments

argument (short) | argument (long) | description | example
---- | ---- | ---- | ----
`-v` | `--verbose` | print extra info | n/a
`-s` | `--source-ec2-ip` | private IPv4 address of an EC2 instance | 10.92.76.45
`-r` | `--source-rds` | name of RDS instance | employee-db-prod
`-d` | `--dest-ip`| (required) private or public IP address of destination | 172.217.12.164

One of `source-ec2-ip` and `source-rds` must be provided. This tool assumes that the source AWS resource (RDS instance or private IP address) resides in the region and the AWS account for which AWS credentials are configured.

The `dest-ip` must always be provided and can be a private or a public IPv4 address. If the `dest-ip` is in AWS and has both a private IP and a public IP address, you might want to run the tool twice, once with each, if you are trying to understand how network traffic might be flowing between the source and desination.

## Examples

```
$ reach.py --source-ec2-ip 10.92.77.247 --dest-ip 10.146.129.72
```

```
$ reach.py --source-ec2-ip 10.92.77.247 --dest-ip 172.217.9.228
```

```
$ reach.py --source-rds billing-detail --dest-ip 10.92.77.247
```

## Tips

If both the source and destination are resources in AWS, you will get the most information by running the tool twice, swapping the source and destination on the second run. Each time the tool is run, it analyzes in the source-to-destiantion direction (in general).

This tool does not handle ALL networking situations. It is meant to gather basic information, present it, and flag obvious issues. Suggestions for improvements are welcome.

## Prerequisites

- [Python3](https://www.python.org/downloads/)
- [boto3](https://github.com/boto/boto3)
- [AWS credentials](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html)
  - IAM privileges must grant `ec2:Describe*` and `rds:Describe*` at minimum.

## Future Enhancements

- Gather/analyze information about Direct Connect
- Specify source/destination port as an input parameter and scope analsys to that port
- Handle ELB/ALB/NLB as a "source"