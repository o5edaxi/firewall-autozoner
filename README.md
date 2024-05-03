# Firewall Autozoner

Zone and interface-based firewalls often inherit rulebases that lack source and especially destination interface/zone constraints.

The firewall rule effectively filters traffic based only on the packet header, and nothing else.

Adding zones to a firewall legacy rulebase can be tedious and essentially requires to either:

1. Identify the original creator of the policy and understand what the intent was, and where the applications are physically and logically located in the network
2. Trust the routing table of the firewall and derive how the packets matching the policy would be forwarded, assigning zones in a way that ensures the policy is coherent with the routing

This script automates the second method by taking a pseudo routing table and a list of policies in csv format, then adding the calculated zones.

To avoid having route lookup operations impact the policy analysis duration in a non-linear manner, the routing space is first flattened on a number line as follows:

```
Routing / zone table:

0.0.0.0/0 ethernet1/1
192.0.2.0/24 ethernet1/2
```

The interesting points are 0.0.0.0, 192.0.1.255, 192.0.2.0, 192.0.2.255, 192.0.3.0, and 255.255.255.255, because these are the beginnings and ends of the sets of addresses which have forwarding equivalence.

```
Flattened / linearized table:

routes = [ [ 0.0.0.0, 'ethernet1/1' ] , [ 192.0.1.255, 'ethernet1/1' ], [ 192.0.2.0, 'ethernet1/2' ], [ 192.0.2.255, 'ethernet1/2' ] , [ 192.0.3.0 , 'ethernet1/1' ], [ 255.255.255.255 , 'ethernet1/1' ] ]
```

Once this is obtained, the zones subtended by a subnet or ip-range can be obtained with a simple slicing of the list, from the member just before the start of the range, to the one just after.

Flattening the routes takes about 5 minutes on a laptop processor for 900-thousand routes (IPv4 FIRT); this can also be cached on disk between runs. The actual analysis then takes just a few seconds even with thousands of policies.

## Usage

```
usage: fw_autozoner.py [-h] [-o OUTPUT_FILE] [-s] [-n] [-a] [-z ZONE_LIMIT] [-b] [-1 SOURCE_COLUMN]
                       [-2 DESTINATION_COLUMN] [-c CSV_SEPARATOR] [-r ADDRESS_SEPARATOR] [-p]
                       [-x {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                       input rib
positional arguments:
  input                 Input csv containing the firewall policies
  rib                   Input csv containing the routes: "192.0.2.0/24","IFACE_OR_ZONE"

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        The name of the output file containing the policy list. Default: zoned.csv
  -s, --source          Analyze the source address column. Default: False
  -n, --null-route      Add ####NULL_ROUTED#### to the zones instead of empty when a destination has no matching
                        routes. Default: False
  -a, --all-zones       Output "any" instead of each individual zone when a given policy contains every single zone in
                        the routing table. Default: False
  -z ZONE_LIMIT, --zone-limit ZONE_LIMIT
                        Output "any" when more than this amount of zones are found for a given policy. Default: no
                        limit
  -b, --split-behavior  Split the policy instead of outputting "any" when the --zone-limit value is exceeded. A column
                        "SPLIT" is added to the output csv to mark the added policies. Default: False
  -1 SOURCE_COLUMN, --source-column SOURCE_COLUMN
                        The column header in the csv corresponding to the source address column. Default: source
  -2 DESTINATION_COLUMN, --destination-column DESTINATION_COLUMN
                        The column header in the csv corresponding to the source address column. Default: destination
  -c CSV_SEPARATOR, --csv-separator CSV_SEPARATOR
                        CSV separator. Default: ","
  -r ADDRESS_SEPARATOR, --address-separator ADDRESS_SEPARATOR
                        CSV separator. Default: ";"
  -p, --pickled-fib     Read the fib from disk (./pickle_fib.pkl) that was saved from a previous run using this
                        option, without recalculating it from the csv rib file. Default: False
  -x {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --debug-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Logging message verbosity. Default: WARNING

```
