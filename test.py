"""Check that the output of the script is identical to zoned-example.csv which has been hand-checked"""
import subprocess
import filecmp
import sys


SCRIPT = 'firewall_autozoner.py'
INPUT = 'policy-example.csv'
INPUT_2 = 'rib-example.csv'
OUTPUT = 'zoned-test.csv'
COMPARE = 'zoned-example.csv'

subprocess.call(['python', SCRIPT, '-s', '-1', 'SRC_IP', '-2', 'DEST_IP', '-n', '-x', 'CRITICAL', '-o', OUTPUT, INPUT,
                 INPUT_2])
if filecmp.cmp(OUTPUT, COMPARE):
    print('Pass')
else:
    print('Fail')
    sys.exit(1)
