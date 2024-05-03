"""Check that the output of the script is identical to zoned-example.csv which has been hand-checked"""
import subprocess
import filecmp
import sys

SCRIPT = 'firewall_autozoner.py'
INPUT = 'policy-example.csv'
INPUT_2 = 'rib-example.csv'

# Full list

output = 'zoned-test-0.csv'
compare = 'zoned-example-0.csv'
subprocess.call(['python', SCRIPT, '-s', '-1', 'SRC_IP', '-2', 'DEST_IP', '-n', '-x', 'CRITICAL', '-o', output, INPUT,
                 INPUT_2])
if filecmp.cmp(output, compare):
    print('Passed test 0')
else:
    print('Failed test 0')
    sys.exit(1)

# Replace "any" when more than 7 zones

output = 'zoned-test-1.csv'
compare = 'zoned-example-1.csv'
subprocess.call(['python', SCRIPT, '-s', '-1', 'SRC_IP', '-2', 'DEST_IP', '-n', '-z', '7', '-x', 'CRITICAL', '-o',
                 output, INPUT, INPUT_2])
if filecmp.cmp(output, compare):
    print('Passed test 1')
else:
    print('Failed test 1')
    sys.exit(1)

# Split the policy when more than 7 zones

output = 'zoned-test-2.csv'
compare = 'zoned-example-2.csv'
subprocess.call(['python', SCRIPT, '-s', '-1', 'SRC_IP', '-2', 'DEST_IP', '-n', '-z', '7', '-b', '-x', 'CRITICAL', '-o',
                 output, INPUT, INPUT_2])
if filecmp.cmp(output, compare):
    print('Passed test 2')
else:
    print('Failed test 2')
    sys.exit(1)

# Replace "any" when the field contains EVERY zone

output = 'zoned-test-3.csv'
compare = 'zoned-example-3.csv'
subprocess.call(['python', SCRIPT, '-s', '-1', 'SRC_IP', '-2', 'DEST_IP', '-a', '-x', 'CRITICAL', '-o', output, INPUT,
                 INPUT_2])
if filecmp.cmp(output, compare):
    print('Passed test 3')
else:
    print('Failed test 3')
    sys.exit(1)
