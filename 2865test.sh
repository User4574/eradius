#!/usr/bin/env bash

t=1
s=0

function describe_test {
  echo "=== Test #$t:" $*
  t=$((t + 1))
}

function run_test {
  pos=$1
  shift
  if [[ $pos == succeed ]]; then
    echo === Execute: $*
    echo === Expect: Succeed
    if $*; then
      echo "✓✓✓ Test succeeded."
      s=$((s + 1))
    else
      echo "✗✗✗ Test failed."
    fi
  else
    echo === Execute: $*
    echo === Expect: Fail
    if $*; then
      echo "✗✗✗ Test succeeded."
    else
      echo "✓✓✓ Test failed."
      s=$((s + 1))
    fi
  fi
}

# Freeradius bugs mean this doesnt work
# See issue https://github.com/FreeRADIUS/freeradius-server/issues/887
# You wouldnt see this kind of jank in eradius!
#
#describe_test Unconfigured client should sliently discard
#run_test fail radclient -x -r 1 localhost auth fake <<.
#User-Name = nemo
#User-Password = arctan
#Packet-Src-IP-Address = 192.0.2.1/32
#.
#echo

describe_test Example 7.1. User Telnet to Specified Host
run_test succeed radtest nemo arctangent localhost 3 xyzzy5461
echo

describe_test Same with incorrect password
run_test fail radtest nemo arctan localhost 3 xyzzy5461
echo

describe_test Example 7.3. User with Challenge-Response card
run_test fail radtest mopsy challenge localhost 7 xyzzy5461
run_test succeed radclient -x localhost auth xyzzy5461 <<.
User-Name = mopsy
User-Password = 99101462
State = 0x3332373639343330
.

echo
echo "Result: $s out of $t tests succeeded."
