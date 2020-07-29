#!/bin/sh

# install some bits and check network conntectivity
echo "=== Testing network"
apk add curl
curl http://google.com
status=$?
if [ $status -ne 0 ]; then
  echo "Error exiting with: $status"
  exit $status
fi

# start the process
echo "=== Starting exploit"
python3 /main.py
status=$?
if [ $status -ne 0 ]; then
  echo "Error exiting with: $status"
  exit $status
fi
exit 0
