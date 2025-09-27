#!/bin/bash

# Soft-RoCE
modprobe rdma_rxe
modprobe ib_uverbs
modprobe rdma_cm
rdma link add rxe_ens18 type rxe netdev ens18
# Start ksmbd
modprobe ksmbd
ksmbd.mountd
ksmbd.control --debug all
ksmbd.control --reload