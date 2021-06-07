#!/bin/sh
sudo fbset -g 1280 800 1280 80 32
sudo mount -t vboxsf -o gid=vboxsf ArchLinuxSharedFolder /shared_folder
sudo mount -t debugfs none /sys/kernel/debug
tmux