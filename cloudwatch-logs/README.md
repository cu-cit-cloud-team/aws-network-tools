# cloudwatch-logs (ct-aws-network-tools)

Tools for CloudWatch Logs

## `insights.py`

Query CloudWatch Logs using Logs Insight

### Arguments

argument (short) | argument (long) | description | example
---- | ---- | ---- | ----
`-v` | `--verbose` | print extra info | n/a
`-g` | `--log-group` | log group name | flow-logs
`-d` | `--days` | days to look back (default 0) | 1
`-H` | `--hours` | hours to look back (default 1) | 1
`-o` | `--output` | output file name (default 'out.csv') | results.csv
`-f` | `--query-file` | file name holding query | flowlog.query

`log-group` and `query-file` must be provided.

### Examples

```
$ ./insights.py --log-group vpc-5ffce339 --query flowlog.query
============================================================
Configuration:
verbose: False
log group: vpc-5ffce339
output file: out.csv
start time: 2019-08-28 11:32:10.816189
end time:   2019-08-28 12:32:10.816187
query:
--------------------------------------------------------------------------------
# Generic flow log query
# Top 10 byte transfers by source and destination IP addresses
stats sum(bytes) as bytesTransferred by srcAddr, dstAddr
| sort bytesTransferred desc
| limit 10
--------------------------------------------------------------------------------
2019-08-28 12:32:16.110410: query 645f3613-e49e-4013-9765-51e98f7267f8 Complete
Records Matched: 714645 Records Scanned: 795993 Bytes Scanned: 109213205
Records Retrieved: 10
$ cat out.csv
srcAddr,dstAddr,bytesTransferred
10.92.164.132,10.92.164.138,947989460
10.92.164.138,10.92.164.132,929375768
169.46.59.7,10.92.164.53,524243911
10.92.164.236,10.92.164.123,479525508
10.92.164.236,10.92.164.14,444210645
10.92.164.53,169.46.59.7,433115903
10.92.164.53,10.92.164.178,273205100
10.92.164.53,10.92.164.136,271683383
169.46.59.7,10.92.164.178,266975233
10.92.82.193,10.92.164.236,247657989
$
```

### Limits

At present AWS API/SDK appears to limit the total number of records returned to 1,000, regardless of how many records result from the query.

### Future Enhancements

- Support absolute dates, instead of just time periods relative to current time

