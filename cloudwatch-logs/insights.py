#!/usr/bin/env python3
"""
Query CloudWatch Logs using Logs Insight
"""
import sys
from pprint import pprint
import argparse
import ipaddress
import socket
import boto3
import datetime
import time
import csv


def convert_results(list):
    """
    Convert query results into a more concise form.

    Example data:
    [[{'field': 'srcAddr', 'value': '40.121.87.244'},
      {'field': 'dstAddr', 'value': '10.92.164.23'},
      {'field': 'srcPort', 'value': '7901'},
      {'field': 'dstPort', 'value': '1521'},
      {'field': 'protocol', 'value': '6'},
      {'field': 'sumBytes', 'value': '3243845'}],
     [{'field': 'srcAddr', 'value': '40.121.87.244'},
      {'field': 'dstAddr', 'value': '10.92.164.23'},
      {'field': 'srcPort', 'value': '1460'},
      {'field': 'dstPort', 'value': '1521'},
      {'field': 'protocol', 'value': '6'},
      {'field': 'sumBytes', 'value': '1982005'}]]
    """
    result = []
    for record in list:
        new_record = {}
        for item in record:
            field = item['field']
            value = item['value']
            new_record[field] = value
        result.append(new_record)
    return result

def main(argv):

    parser = parser = argparse.ArgumentParser(description='pull flow log data from CloudWatch Logs using Logs Insight')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help="show more info")
    parser.add_argument('-g', '--log-group', required=True, help="log group name")
    parser.add_argument('-d', '--days', required=False, default='0', help="look back days")
    parser.add_argument('-H', '--hours', required=False, default='1', help="look back hours")
    parser.add_argument('-o', '--output', required=False, default='out.csv', help="output file name")
    parser.add_argument('-f', '--query-file', required=True, help="query input file name")
    args = parser.parse_args()

    verbose = args.verbose
    log_group_name = args.log_group
    end_time =  datetime.datetime.now()
    start_time = datetime.datetime.now() - datetime.timedelta(days=int(args.days), hours=int(args.hours))
    output_file = args.output
    query_file = args.query_file

    with open(query_file, 'r') as file:
        query = file.read()

    print("============================================================")
    print("Configuration:")
    print(f"verbose: {str(verbose)}")
    print(f"log group: {log_group_name}")
    print(f"output file: {output_file}")
    print(f"start time: {start_time}")
    print(f"end time:   {end_time}")
    print('query:\n'+'-'*80)
    print(query)
    print('-'*80)


    ec2_client = boto3.client('ec2')
    logs_client = boto3.client('logs')

    response = logs_client.start_query(
        logGroupName=log_group_name,
        # logGroupNames=[
        #     'string',
        # ],
        startTime=int(start_time.timestamp()),
        endTime=int(end_time.timestamp()),
        queryString=query,
        # limit=20
    )
    if verbose:
        pprint(response)
    query_id = response['queryId']

    status = 'Scheduled'
    while status in ['Running', 'Scheduled']:
        time.sleep(5)
        response = logs_client.describe_queries(
            logGroupName=log_group_name,
            # status='Complete'|'Failed'|'Cancelled',
            maxResults=999,
            # nextToken='string'
        )
        target_query = None
        status = None
        for q in response['queries']:
            if q['queryId'] == query_id:
                target_query = q
                status = q['status']
                break
        print(f"{str(datetime.datetime.now())}: query {query_id} {status}")

    response = logs_client.get_query_results(
        queryId=query_id
    )
    if verbose:
        pprint(response)
    response['statistics']['recordsMatched']
    print(f"Records Matched: {int(response['statistics']['recordsMatched'])} Records Scanned: {int(response['statistics']['recordsScanned'])} Bytes Scanned: {int(response['statistics']['bytesScanned'])}")
    result = convert_results(response['results'])
    if verbose:
        pprint(result)
    print(f"Records Retrieved: {len(result)}")
    if len(result) > 0:
        with open(output_file, mode='w') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=result[0].keys())
            writer.writeheader()
            for record in result:
                writer.writerow(record)

if __name__ == "__main__":
    main(sys.argv[1:])
