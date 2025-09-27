#!/bin/bash

ksmbd.control --shutdown
sleep 5
modprobe -r ksmbd