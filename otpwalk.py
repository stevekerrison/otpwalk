#!/usr/bin/env python3
"""
OTP Walk

More of a sprint than a walk, through OTP values, looking for duplicates and recording some simple stats.

Author: Steve Kerrison
License: MIT

Usage:
  otpwalk.py [--mode=<m>] [--limit=<l>]
  otpwalk.py (-h | --help)
  otpwalk.py --version

Options:
  -h --help         This help text.
  --version         Version info.
  --mode=<m>        OTP mode, either totp or hotp [default: totp].
  --limit=<l>       Limit (iterations/seconds for hotp/totp) [default: 100000]

"""

from docopt import docopt
from pyotp import TOTP, HOTP, random_base32

def walk(mode, limit):
    """
    Walk through an OTP generator looking for duplicates
    """
    # Generate a secret. This would normally be agreed between client & server
    secret = random_base32()
    # Setup the appropriate OTP generator (they're the same really, just one turns groups of seconds into counts)
    limit = int(limit)
    if mode == 'totp':
        interval = 30
        otp = TOTP(secret, interval=interval)
    elif mode == 'hotp':
        interval = 1
        otp = HOTP(secret)
    else:
        raise ValueError("--mode must be either 'totp' or 'hotp'")
    # Data structures for tracking
    histogram = {value: 0 for value in range(1000000)}
    last_seen = {value: None for value in range(1000000)}
    dupecount = {}
    dupeintervals = []
    # Go for a walk...
    for count in range(0, limit, interval):
        value = int(otp.at(count))
        # We care about the interval between duplicates of each number, not interval between any duplicate
        if last_seen[value] is not None:
            dupeintervals.append((count - last_seen[value]) // interval)
        last_seen[value] = count
        histogram[value] += 1
        if histogram[value] > 1:
            if histogram[value] not in dupecount:
                dupecount[histogram[value]] = set([value])
            else:
                dupecount[histogram[value]].add(value)
            if histogram[value] > 2:
                # When a value is duplicated multiple times, we remove its old entry
                dupecount[histogram[value] - 1].remove(value)

    # Print some stats and data
    print(f"""
After {limit//interval} iterations
----------------------------------

Secret: {secret}
Number of duplicates: {sum([(dup - 1) * len(val) for dup, val in dupecount.items()])}
Dupe occurrences and values: {dupecount}
Intervals between dupes: {dupeintervals}
Average dupe interval: {sum(dupeintervals) // max(len(dupeintervals),1)}
    """)

if __name__ == "__main__":
    ARGS = docopt(__doc__, version="OTP Walk version 0")
    walk(ARGS['--mode'], ARGS['--limit'])
