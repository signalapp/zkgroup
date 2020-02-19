#!/bin/bash

#
# copy_repo.sh <source> <destination>
#
# Copy the given node directory to the artifact repository.
#
# Example:
# zkgroup/ffi/node$ scripts/copy_repo.sh . ../../../signal-zkgroup-node
#

rsync -avrq \
  --exclude='dist/test' \
  --exclude='node_modules' \
  --exclude='scripts' \
  --exclude='test' \
  --exclude='.gitignore' \
  --exclude='.nvmrc' \
  --exclude='Makefile' \
  --exclude='tsconfig.json' \
  --exclude='BUILDING.md' \
  --exclude='README.md' \
   $1 $2

# Ensure that the LICENSE file is up to date.
cp -f $1/../../LICENSE $2

# Ensure that the README.md file is up to date.
cp -f $1/../../README.md $2
