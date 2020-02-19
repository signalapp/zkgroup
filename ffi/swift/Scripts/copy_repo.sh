#!/bin/bash

#
# copy_repo.sh <source> <destination>
#
# Copy the given swift directory to the artifact repository.
#
# Example:
# zkgroup/ffi/swift$ Scripts/copy_repo.sh . ../../../signal-zkgroup-swift
#

rsync -avrq \
  --exclude='Scripts' \
  --exclude='.gitignore' \
  --exclude='Makefile' \
  --exclude='BUILDING.md' \
  --exclude='README.md' \
   $1 $2

# Ensure that the LICENSE file is up to date.
cp -f $1/../../LICENSE $2

# Ensure that the README.md file is up to date.
cp -f $1/../../README.md $2
