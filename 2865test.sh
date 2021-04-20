#!/usr/bin/env bash

t=1

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
    $* \
      && echo "✓✓✓ Test succeeded." \
      || echo "✗✗✗ Test failed."
  else
    echo === Execute: $*
    echo === Expect: Fail
    $* \
      && echo "✗✗✗ Test succeeded." \
      || echo "✓✓✓ Test failed."
  fi
}

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
