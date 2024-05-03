"""Takes a csv file containing firewall policies, a routing table, and adds the correct source/destination interface
or zone to each policy"""
import csv
import sys
import argparse
import logging
import ipaddress
import pickle


MAX_WAIT_SECONDS = 3600
IP_VERSIONS = {4: (32, '0.0.0.0/0'), 6: (128, '::/0')}
FIB_DISK_CACHE = 'pickle_fib.pkl'


def populate_linearized_fib(ribfile, sep):
    """Takes a csv file as in '192.0.2.0/24, IFACE_OR_ZONE' and returns a list of addresses in decimal form
    corresponding to the point in the address space where the forwarding decision changes, e.g.
    [ [ 0, 'ethernet1/1' ] , [ 3221225983, 'ethernet1/1' ], [ 3221225984, 'ethernet1/2' ] ,
    [ 3221226239, 'ethernet1/2' ] , [ 3221226240 , 'ethernet1/1' ], [ 4294967295 , 'ethernet1/1' ] ]
    For a routing table with routes: 0.0.0.0/0 ethernet1/1; 192.0.2.0/24 ethernet1/2
    The interesting points are 0.0.0.0, 192.0.1.255, 192.0.2.0, 192.0.2.255, 192.0.3.0, and 255.255.255.255"""
    rib_dict_list = {ver: [{} for x in range(0, bits[0] + 1)] for ver, bits in IP_VERSIONS.items()}
    fib_list = {ver: [] for ver in IP_VERSIONS}
    with open(ribfile, 'r', encoding='utf-8') as a:
        reader = list(csv.reader(a, delimiter=sep))
    try:
        logging.debug('Checking if rib file has a header')
        ipaddress.ip_network(reader[0][0], strict=False)
        if '.' in reader[0][0] or ':' in reader[0][0]:
            start = 0
        else:
            logging.info('Found header in rib file')
            start = 1
    except ipaddress.AddressValueError:
        logging.info('Found header in rib file')
        start = 1
    for idx, line in enumerate(reader[start:], start=1):
        if not line[1]:
            logging.error('route %s has no interface, skipping', line)
            continue
        item = ipaddress.ip_network(line[0], strict=False)
        ipver = item.version
        logging.debug('Analyzing line %s of rib file', line)
        try:
            rib_dict_list[ipver][item.prefixlen][item].add(line[1])
            logging.debug('ECMP/Duplicate route found: %s', line[0])
        except KeyError:
            rib_dict_list[ipver][item.prefixlen][item] = {line[1]}
        logging.debug('Added to rib: %s', item)
        if idx % 10000 == 0:
            logging.warning('Added %d routes to RIB', idx)
    # Add a default if not present
    for ver, bits in IP_VERSIONS.items():
        if not rib_dict_list[ver][0]:
            rib_dict_list[ver][0][ipaddress.ip_network(bits[1])] = {'####NULL_ROUTED####'}
    """
    rib_dict_list[v4]:
    level 25: { 192.0.2.0/25: eth1 }
    level 24: {}
    level 23: { 192.0.2.0/23: eth2, 192.0.100.0/23: eth3 }
    1. start analyzing the highest level
    2. check for supernets to split in the lower levels
    3. skip empty level 24
    4. look into level 23
    5. check if 192.0.2.0/(25 - 1 = 24) exists in level 23 -> no  match
    6. check if 192.0.2.0/(25 - 2 = 23) exists in level 23 -> match, guaranteed to contain the /25
    7. fragment 192.0.2.0/23 using 192.0.2.0/25 and add the fragments to level 23 except for 192.0.2.0/25 itself
    8. remove 192.0.2.0/23 from level 23
    level 25: { 192.0.2.0/25: eth1 }
    level 24: {}
    level 23: { 192.0.2.128/25: eth2, 192.0.3.0/24: eth2, 192.0.100.0/23: eth3 }
    9. repeat for every other member of level 25 then move to the next level and repeat
    10. once all levels are coalesced the result describes the entire forwarding space with no overlapping routes
    11. this can be turned into a list of integers identifying the start and end of each route
    """
    for ver, bits in IP_VERSIONS.items():
        supernet_cache = {}
        for plen in range(bits[0], 0, -1):  # 32 to 1
            logging.info('Analyzing prefix length %d of v%drib', plen, ver)
            for idx, route in enumerate(rib_dict_list[ver][plen], start=1):
                logging.debug('Checking route %s in lower levels', route)
                iter_supernet_cache = supernet_cache.copy()
                for old_plen, old_supernet in iter_supernet_cache.items():
                    if not route.overlaps(old_supernet):
                        del supernet_cache[old_plen]
                for lvl_cursor in range(plen - 1, -1, -1):  # x-1 to 0
                    done = False
                    if route in rib_dict_list[ver][lvl_cursor]:
                        logging.debug('Route %s in level %d is already present in lower level, no need to split', route,
                                      plen)
                        break  # Route comes from a previous split operation
                    for decreasing_plen in range(route.prefixlen - 1, lvl_cursor - 1, -1):  # x-1 to smallest plen in
                        # the level
                        if decreasing_plen in supernet_cache:
                            supernet = supernet_cache[decreasing_plen]
                        else:
                            supernet = route.supernet(new_prefix=decreasing_plen)
                            supernet_cache[decreasing_plen] = supernet
                        if supernet in rib_dict_list[ver][lvl_cursor]:
                            logging.debug('Supernet %s of route %s found in level %d', supernet, route, lvl_cursor)
                            # Fragment the supernet, inherit its interface for fragments and then discard the supernet
                            for subnet in supernet.address_exclude(route):
                                if subnet != route:  # Remove original route from fragments
                                    logging.debug('Adding fragment %s of supernet to level %d', subnet, lvl_cursor)
                                    rib_dict_list[ver][lvl_cursor][subnet] = rib_dict_list[ver][lvl_cursor][supernet]
                            logging.debug('Removing supernet %s from level %d', supernet, lvl_cursor)
                            del rib_dict_list[ver][lvl_cursor][supernet]
                            done = True
                            break
                    if done:
                        break
                if idx % 10000 == 0:
                    logging.warning('Sliced %d of %d IPv%d routes in plen level %d', idx, len(rib_dict_list[ver][plen]),
                                    ver, plen)
    # Add all levels to one big dictionary preferring the higher prefix length entries
    logging.info('Done splitting routes')
    logging.info('Coalescing and sorting levels')
    big_dict = {}
    rib_list = {}
    for ver in IP_VERSIONS:
        big_dict[ver] = {}
        for dicti in reversed(rib_dict_list[ver]):
            if dicti:
                z = dicti.copy()
                z.update(big_dict[ver])
                big_dict[ver] = z.copy()
        rib_list[ver] = [[ipaddress.ip_network(x), list(y)] for x, y in big_dict[ver].items()]
        # Order routes on the number line
        rib_list[ver].sort(key=lambda x: x[0].network_address, reverse=False)
        for r in rib_list[ver]:
            fib_list[ver].append([int(r[0][0]), r[1]])
            logging.debug('Added start of route to the address line: %s', fib_list[ver][-1])
            if r[0][-1] != r[0][0]:
                fib_list[ver].append([int(r[0][-1]), r[1]])
                logging.debug('Added end of route to the address line: %s', fib_list[ver][-1])
            else:
                logging.debug('Single IP route, not adding end to address line')
    fib_list_compressed = {ver: [] for ver in IP_VERSIONS}
    # Max 2 identical consecutive zones for efficiency
    # [ a_str, a_end, b_srt, b_end, b_srt, b_end, a_str, a_end ] -> [ a_str, a_end, b_srt, b_end, a_str, a_end ]
    logging.info('Compressing adjacent routes with the same interface on the fib')
    for ver in IP_VERSIONS:
        prev = [None, None]
        for idx, point in enumerate(fib_list[ver]):
            if point[1] != prev:
                logging.debug('Interface change from %s to %s at address %s, marking it', prev, point[1], point[0])
                if idx > 1 and fib_list_compressed[ver][-1] != fib_list[ver][idx -1]: # Don't add host routes twice
                    fib_list_compressed[ver].append(fib_list[ver][idx - 1])
                fib_list_compressed[ver].append(point)
                prev = point[1]
        # Cap off the list if not
        if fib_list_compressed[ver][-1] != fib_list[ver][-1]:
            fib_list_compressed[ver].append(fib_list[ver][-1])
    logging.info('Done compressing fib')
    return fib_list_compressed


def zone_finder(netobj, fib, tot_zones, null_route):
    """Takes an ipaddress network and returns the possible interfaces or zones those packets might be forwarded out
    of, based on a pseudo fib"""
    netobj_version = netobj.version
    if netobj.prefixlen == 0:
        return tot_zones[netobj_version]
    logging.debug('Object is IPv%d', netobj_version)
    logging.debug('Looking up possible routes for network %s', netobj)
    object_start = int(netobj[0])
    object_end = int(netobj[-1])
    slice_start = 0
    slice_end = None
    start_found = False
    for idx, element in enumerate(fib[netobj_version]):
        if not start_found:
            if object_start < element[0]:
                slice_start = idx - 1
                start_found = True
            elif object_start == element[0]:
                slice_start = idx
                start_found = True
        if start_found:
            if object_end < element[0]:
                # We are past the objective so by slicing list[x:y] we get only the zone at place y-1
                slice_end = idx
                break
            elif object_end == element[0]:
                # We are on the exact route delimiter, so we want to include it fully
                slice_end = idx + 1
                break
    if slice_end == slice_start:
        # List[x:x] doesn't return anything. Overslicing also doesn't cause any IndexError, so we can do list[x:x+1]
        slice_end += 1
    zones = [x for y in fib[netobj_version][slice_start:slice_end] for x in y[1]]
    zones = list(set(zones))
    logging.debug('Checked all zones for subnet %s: %s', netobj, zones)
    if '####NULL_ROUTED####' in zones:
        if len(zones) == 1:
            logging.warning('No destinations in %s match an existing route', netobj)
        else:
            logging.warning('Some destinations in %s do not match any routes', netobj)
        if not null_route:
            zones.remove('####NULL_ROUTED####')
    return zones


def resolve_net_or_range(net_or_range):
    """Takes a subnet or range and looks it up in express_cache{}"""
    # Handle IP Ranges e.g. 192.0.2.1-192.0.2.10 by converting to networks
    range_check = net_or_range.split('-')
    if len(range_check) == 2:
        logging.debug('Detected IP range %s, splitting into subnets', range_check)
        range_start = ipaddress.ip_address(range_check[0])
        range_end = ipaddress.ip_address(range_check[1])
        partial_zones = []
        for subnet in ipaddress.summarize_address_range(range_start, range_end):
            logging.debug('Checking subnet %s part of range', subnet)
            net = ipaddress.ip_network(subnet, strict=False)
            partial_zones += express_cache[net]
        return partial_zones
    net = ipaddress.ip_network(net_or_range, strict=False)
    logging.debug('Checking subnet %s', net)
    return express_cache[net]


def explode_object(net_or_range):
    """Takes a subnet or IP range, turns it into subnets if needed and outputs as list of IPvXNetwork()"""
    # Handle IP Ranges e.g. 192.0.2.1-192.0.2.10 by converting to networks
    range_check = net_or_range.split('-')
    if len(range_check) == 2:
        logging.debug('Detected IP range %s, splitting into subnets', range_check)
        range_start = ipaddress.ip_address(range_check[0])
        range_end = ipaddress.ip_address(range_check[1])
        return ipaddress.summarize_address_range(range_start, range_end)
    return [ipaddress.ip_network(net_or_range, strict=False)]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Takes a csv file containing firewall policies, a routing table, and '
                                                 'adds the correct source/destination interface or zone for each '
                                                 'policy. Addresses can be hosts, nets, or ranges in the form '
                                                 '192.0.2.1, 192.0.2.0/24, 192.0.2.100/24, 192.0.2.1-192.0.2.100, '
                                                 '2001:db8::1, 2001:db8::/64, 2001:db8::a/64, '
                                                 '2001:db8::1-2001:db8::100')
    parser.add_argument('input', type=str, help='Input csv containing the firewall policies')
    parser.add_argument('rib', type=str, help='Input csv containing the routes: "192.0.2.0/24","IFACE_OR_ZONE"')
    parser.add_argument('-o', '--output-file', type=str, default='zoned.csv',
                        help='The name of the output file containing the policy list. Default: zoned.csv')
    parser.add_argument('-s', '--source', action='store_true', default=False, help='Analyze the source address column. '
                                                                              'Default: False')
    parser.add_argument('-n', '--null-route', action='store_true', default=False, help='Add ####NULL_ROUTED#### to the '
                                                                                  'zones instead of empty when a '
                                                                                  'destination has no matching routes. '
                                                                                  'Default: False')
    parser.add_argument('-a', '--all-zones', action='store_true', default=False, help='Output "any" instead of each '
                                                                                'individual zone when a given policy '
                                                                                'contains every single zone in the '
                                                                                'routing table. Default: False')
    parser.add_argument('-z', '--zone-limit', type=int, default=0, help='Output "any" when more than this amount of '
                                                                        'zones are found for a given policy. Default: '
                                                                        'no limit')
    parser.add_argument('-b', '--split-behavior', action='store_true', default=False, help='Split the policy instead of'
                                                                                           ' outputting "any" when the '
                                                                                           '--zone-limit value is '
                                                                                           'exceeded. A column "SPLIT" '
                                                                                           'is added to the output csv '
                                                                                           'to mark the added policies.'
                                                                                           ' Default: False')
    parser.add_argument('-1', '--source-column', type=str, default='source',
                        help='The column header in the csv corresponding to the source address column. Default: source')
    parser.add_argument('-2', '--destination-column', type=str, default='destination',
                        help='The column header in the csv corresponding to the source address column. Default: '
                             'destination')
    parser.add_argument('-c', '--csv-separator', type=str, default=',', help='CSV separator. Default: ","')
    parser.add_argument('-r', '--address-separator', type=str, default=';', help='CSV separator. Default: ";"')
    parser.add_argument('-p', '--pickled-fib', action='store_true', default=False, help='Read the fib from disk '
                                                                                   f'(./{FIB_DISK_CACHE}) that was '
                                                                                   'saved from a previous run using '
                                                                                   'this option, without recalculating '
                                                                                   'it from the csv rib file. Default: '
                                                                                   'False')
    parser.add_argument('-x', '--debug-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        default='WARNING', help='Logging message verbosity. Default: WARNING')
    args = parser.parse_args()
    logging.basicConfig(level=args.debug_level, format='%(asctime)s [%(levelname)s] %(message)s')
    logging.debug('Starting with args %s', args)
    if args.pickled_fib:
        try:
            logging.warning('Trying to get fib from file %s', FIB_DISK_CACHE)
            with open(FIB_DISK_CACHE, 'rb') as f:
                fib_table = pickle.load(f)
        except FileNotFoundError:
            logging.warning('Fib cache not present on disk, creating it for next time...')
            fib_table = populate_linearized_fib(args.rib, args.csv_separator)
            logging.warning('Dumping fib to disk')
            with open(FIB_DISK_CACHE, 'wb') as f:
                pickle.dump(fib_table, f)
    else:
        fib_table = populate_linearized_fib(args.rib, args.csv_separator)
    total_zones = {}
    for ver in IP_VERSIONS:
        total_zones[ver] = [x for y in fib_table[ver] for x in y[1]]
        total_zones[ver] = list(set(total_zones[ver]))
        if not args.null_route and '####NULL_ROUTED####' in total_zones[ver]:
            total_zones[ver].remove('####NULL_ROUTED####')
    output_list = []
    logging.info('Opening file %s', args.input)
    with open(args.input, 'r', encoding='utf-8') as f:
        parsed = list(csv.reader(f, delimiter=args.csv_separator))
        logging.debug('%s', parsed)
    if '####NULL_ROUTED####' in str(parsed):
        logging.critical('Found protected string "####NULL_ROUTED####" in policy file. This zone is used internally '
                         'and cannot be present. Exiting...')
        sys.exit(1)
    if args.source:
        try:
            logging.info('Looking for source column %s', args.source_column)
            SRC_INDEX = parsed[0].index(args.source_column)
            logging.info('Found source column')
            try:
                parsed[0].index(f'{args.source_column}_ZONE')
                logging.critical('Output column %s_ZONE is already present in the file. Exiting...',
                                 args.source_column)
                sys.exit(1)
            except ValueError:
                pass
        except ValueError:
            logging.critical('Source column %s not present in the file. Exiting...', args.source_column)
            sys.exit(1)
    else:
        logging.info('Source address will not be analyzed')
        SRC_INDEX = False
    try:
        logging.info('Looking for destination column %s', args.destination_column)
        DEST_INDEX = parsed[0].index(args.destination_column)
        logging.info('Found destination column')
        try:
            parsed[0].index(f'{args.destination_column}_ZONE')
            logging.critical('Output column %s_ZONE is already present in the file. Exiting...',
                             args.destination_column)
            sys.exit(1)
        except ValueError:
            pass
    except ValueError:
        logging.critical('Destination column %s not present in the file. Exiting...', args.destination_column)
        sys.exit(1)
    HEADER = parsed[0]
    if SRC_INDEX:
        HEADER.insert(SRC_INDEX, f'{args.source_column}_ZONE')
    HEADER.insert(DEST_INDEX, f'{args.destination_column}_ZONE')
    if args.split_behavior:
        HEADER.append('SPLIT')
    output_list.append(HEADER)
    objects_list = []
    logging.info('Gathering all sources and destinations')
    for idx, row in enumerate(parsed[1:], start=1):
        if SRC_INDEX:
            for member in row[SRC_INDEX].split(args.address_separator):
                objects_list.append(member)
        for member in row[DEST_INDEX].split(args.address_separator):
            objects_list.append(member)
        if idx % 1000 == 0:
            logging.warning('Searched %d of %d policies for objects', idx, len(parsed[1:]))
    objects_list = list(set(objects_list))
    exploded_list = []
    for objec in objects_list:
        exploded_list += explode_object(objec)
    exploded_list = list(set(exploded_list))
    # Order by increasing prefix length
    exploded_list.sort(key=lambda x: x.prefixlen)
    logging.info('Resolving all objects found in policies')
    express_cache = {}
    done = set()
    cur_plen = exploded_list[0].prefixlen
    for idx, obj in enumerate(exploded_list, start=1):
        if idx % 100 == 0:
            logging.warning('Resolved %d of %d objects', idx, len(exploded_list))
        if obj.prefixlen != cur_plen:
            # Done with previous plength. Search all objects of that plength for single-zone objects
            # If larger subnet resolves to 1 zone only, it is also valid for all smaller subnets contained in it
            for ob in exploded_list:
                if ob.prefixlen == cur_plen and len(express_cache[ob]) == 1:
                    for o in exploded_list:
                        if o not in done and o.prefixlen > ob.prefixlen and o.overlaps(ob):
                            logging.info('Object %s is guaranteed to resolve to the same zones as %s which covers '
                                         'it, will skip analysis', o, ob)
                            express_cache[o] = express_cache[ob]
                            done.add(o)
        cur_plen = obj.prefixlen
        if obj in done:
            logging.info('Zones for object %s inherited from covering object already analyzed, skipping', obj)
            continue
        express_cache[obj] = zone_finder(obj, fib_table, total_zones, args.null_route)
        done.add(obj)
    logging.info('Finished resolving raw objects')
    logging.info('Reassembling any IP Ranges and building the final lookup table')
    final_cache = {}
    for net_or_range in objects_list:
        logging.debug('Checking object %s', net_or_range)
        final_cache[net_or_range] = resolve_net_or_range(net_or_range)
    total_zones_all_proto = set([x for xs in total_zones for x in total_zones[xs]])
    try:
        total_zones_all_proto.remove('####NULL_ROUTED####')
    except KeyError:
        pass
    for idx, row in enumerate(parsed[1:], start=1):
        logging.debug('Checking policy %s', row)
        if SRC_INDEX:
            src_zones = []
            for member in row[SRC_INDEX].split(args.address_separator):
                logging.debug('Checking source address %s in policy', member)
                src_zones += final_cache[member]
        dest_zones = []
        for member in row[DEST_INDEX].split(args.address_separator):
            logging.debug('Checking destination address %s in policy', member)
            dest_zones += final_cache[member]
        logging.debug('Deduping and sorting zone list alphabetically')
        if SRC_INDEX:
            src_zones = list(set(src_zones))
            # Sort the zones alphabetically when the policy has multiple zones
            src_zones.sort()
            any_check = set(src_zones)
            try:
                any_check.remove('####NULL_ROUTED####')
            except KeyError:
                pass
            if args.all_zones and any_check == total_zones_all_proto:
                logging.warning('Policy %s source contains all the zones, replacing with "any" due to -a flag', row)
                row.insert(SRC_INDEX, [['any']])
            elif args.zone_limit and len([s for s in src_zones if s != '####NULL_ROUTED####']) > args.zone_limit:
                if args.split_behavior:
                    logging.warning('Splitting policy %s due to -z and -b flag', row)
                    chunks = []
                    chunk = []
                    for idx, zone in enumerate(src_zones, start=0):
                        if idx != 0 and idx % args.zone_limit == 0:
                            chunks.append(chunk)
                            chunk = []
                        chunk.append(zone)
                    # Add the last little chunk if len < zone_limit
                    if chunk:
                        chunks.append(chunk)
                    row.insert(SRC_INDEX, chunks)
                else:
                    logging.warning('Number of source zones %d for policy %s exceeds the configured maximum of %d, '
                                    'replacing with "any"', len(src_zones), row, args.zone_limit)
                    row.insert(SRC_INDEX, [['any']])
            else:
                if not src_zones:
                    logging.warning('No source zones found for policy %s, probably missing routes', row)
                row.insert(SRC_INDEX, [src_zones])
        dest_zones = list(set(dest_zones))
        dest_zones.sort()
        any_check = set(dest_zones)
        try:
            any_check.remove('####NULL_ROUTED####')
        except KeyError:
            pass
        if args.all_zones and any_check == total_zones_all_proto:
            logging.warning('Policy %s destination contains all the zones, replacing with "any" due to -a flag', row)
            row.insert(DEST_INDEX, [['any']])
        elif args.zone_limit and len([s for s in dest_zones if s != '####NULL_ROUTED####']) > args.zone_limit:
            if args.split_behavior:
                logging.warning('Splitting policy %s due to -z and -b flag', row)
                chunks = []
                chunk = []
                for idx, zone in enumerate(dest_zones, start=0):
                    if idx != 0 and idx % args.zone_limit == 0:
                        chunks.append(chunk)
                        chunk = []
                    chunk.append(zone)
                # Add the last little chunk if len < zone_limit
                if chunk:
                    chunks.append(chunk)
                row.insert(DEST_INDEX, chunks)
            else:
                logging.warning('Number of destination zones %d for policy %s exceeds the configured maximum of %d, '
                                'replacing with "any"', len(dest_zones), row, args.zone_limit)
                row.insert(DEST_INDEX, [['any']])
        else:
            if not dest_zones:
                logging.error('No destination zones found for policy %s, probably missing routes', row)
            row.insert(DEST_INDEX, [dest_zones])
        if SRC_INDEX:
            logging.debug('Source zones for policy %s:', row)
            logging.debug('%s', src_zones)
        logging.debug('Destination zones for policy %s:', row)
        logging.debug('%s', dest_zones)
        logging.debug('The final policy looks like:')
        logging.debug('%s', row)
        final_row = row.copy()
        if SRC_INDEX:
            if args.split_behavior:
                if len(row[SRC_INDEX]) > 1 or len(row[DEST_INDEX]) > 1:
                    final_row.append('true')
                else:
                    final_row.append('false')
            for src_item in row[SRC_INDEX]:
                final_row[SRC_INDEX] = args.address_separator.join(src_item)
                for dest_item in row[DEST_INDEX]:
                    final_row[DEST_INDEX] = args.address_separator.join(dest_item)
                    output_list.append(final_row.copy())
        else:
            if args.split_behavior:
                if len(row[DEST_INDEX]) > 1:
                    final_row.append('true')
                else:
                    final_row.append('false')
            for dest_item in row[DEST_INDEX]:
                final_row[DEST_INDEX] = args.address_separator.join(dest_item)
                output_list.append(final_row.copy())
        if idx % 1000 == 0:
            logging.warning('Done checking %d of %d policies', idx, len(parsed[1:]))
    logging.info('Writing csv to file %s', args.output_file)
    with open(args.output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=args.csv_separator)
        writer.writerows(output_list)
