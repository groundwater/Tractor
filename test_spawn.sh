#!/bin/bash
# Wait for Tractor to attach
sleep 3

echo "Spawning child processes..."

# Bunch of short-lived children
ls /tmp &
sleep 0.1 &
echo "hello" > /dev/null &
cat /etc/hosts > /dev/null &
wc -l /etc/passwd &
date &
uname -a &
whoami &
pwd &
env > /dev/null &

# Nested children
bash -c 'sleep 0.2; echo nested1' &
bash -c 'bash -c "echo deeply_nested"' &
bash -c 'for i in 1 2 3; do echo $i > /dev/null; done' &

wait
echo "All children done."
sleep 2
# test edit 3
