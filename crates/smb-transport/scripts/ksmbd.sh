#!/bin/bash

# Soft-RoCE
modprobe rdma_rxe
modprobe ib_uverbs
modprobe rdma_cm
rdma link add rxe_ens18 type rxe netdev ens18
sleep 0.1

# Start ksmbd
modprobe ksmbd
sleep 0.1

ksmbd.mountd
sleep 1

ksmbd.control --debug all
sleep 0.5
ksmbd.control --reload