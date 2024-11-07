#! /bin/sh

set -ex

docker build -t rumqttd .

version=`awk -F ' = ' '$1 ~ /version/ { gsub(/[\"]/, "", $2); printf("%s",$2) }' rumqttd/Cargo.toml`

