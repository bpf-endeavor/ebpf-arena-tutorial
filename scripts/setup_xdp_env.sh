#!/bin/bash

# Prepare a quick test environment for XDP

sudo ip netns add n2
sudo ip link add veth1 type veth peer name veth2 netns n2
sudo ip link set veth1 up
sudo ip addr add 10.10.0.1/24 dev veth1

sudo ip netns exec n2 ip link set veth2 up
sudo ip netns exec n2 ip addr add 10.10.0.2/24 dev veth2
