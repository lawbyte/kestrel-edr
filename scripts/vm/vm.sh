#!/usr/bin/env bash
# Disposable Windows 11 lab VM for Kestrel (QEMU/KVM inside WSL2 or any Linux host with /dev/kvm).
#
#   scripts/vm/vm.sh install            # unattended install from win11.iso (~20-40 min), then snapshot "clean"
#   scripts/vm/vm.sh start | stop       # boot / shut down (ACPI, then kill after 90 s)
#   scripts/vm/vm.sh snapshot NAME      # offline internal qcow2 snapshot (VM must be stopped)
#   scripts/vm/vm.sh revert NAME        # revert to snapshot (VM must be stopped)
#   scripts/vm/vm.sh ssh [CMD...]       # PowerShell over SSH as labadmin (key auth)
#   scripts/vm/vm.sh put LOCAL REMOTE   # scp a file into the guest
#   scripts/vm/vm.sh get REMOTE LOCAL   # scp a file out of the guest
#   scripts/vm/vm.sh screenshot FILE    # PNG of the guest display
#   scripts/vm/vm.sh wait-ssh [SECS]    # wait until sshd answers
#
# State lives in $KVM_DIR (default ~/kestrel-vm): win11.iso (Windows 11 Enterprise Evaluation from
# https://www.microsoft.com/evalcenter/download-windows-11-enterprise), disk.qcow2, lab_key, passwords.
# Inside the guest, the host is 10.0.2.2 (QEMU user networking); guest sshd is forwarded to
# 127.0.0.1:$SSH_PORT. Lab only: the guest is meant to be destroyed.
set -euo pipefail

KVM_DIR=${KVM_DIR:-$HOME/kestrel-vm}
SSH_PORT=${SSH_PORT:-2222}
VNC_DISPLAY=${VNC_DISPLAY:-5}
CPUS=${CPUS:-4}
MEM=${MEM:-8192}
HERE=$(cd "$(dirname "$0")" && pwd)
SELF="$HERE/$(basename "$0")"
mkdir -p "$KVM_DIR"
cd "$KVM_DIR"

DISK=disk.qcow2
MON=$KVM_DIR/mon.sock
PIDF=$KVM_DIR/qemu.pid

running() { [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; }
mon() { printf '%s\n' "$1" | socat - "UNIX-CONNECT:$MON" >/dev/null 2>&1 || true; }

ssh_opts=(-i "$KVM_DIR/lab_key" -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=15)

qemu_run() { # $@ = extra args
    qemu-system-x86_64 -name kestrel-lab -enable-kvm -machine q35 \
        -cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time \
        -smp "$CPUS" -m "$MEM" -rtc base=localtime \
        -device ahci,id=ahci \
        -drive file="$DISK",if=none,id=d0,format=qcow2,cache=unsafe -device ide-hd,drive=d0,bus=ahci.0,bootindex=1 \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" -device e1000e,netdev=n0 \
        -device qemu-xhci -device usb-tablet \
        -vga std -vnc "127.0.0.1:${VNC_DISPLAY}" \
        -monitor "unix:$MON,server,nowait" -pidfile "$PIDF" -daemonize "$@"
}

cmd=${1:-help}; shift || true
case "$cmd" in
install)
    [ -s win11.iso ] || { echo "missing $KVM_DIR/win11.iso" >&2; exit 1; }
    running && { echo "VM already running" >&2; exit 1; }
    [ -f lab_key ] || ssh-keygen -q -t ed25519 -N '' -f lab_key -C kestrel-lab
    [ -f admin_pw.txt ] || printf 'Adm-%s!' "$(openssl rand -hex 10)" > admin_pw.txt
    [ -f user_pw.txt ] || printf 'Usr-%s!' "$(openssl rand -hex 10)" > user_pw.txt
    rm -rf setupcd && mkdir setupcd
    sed -e "s|@@ADMIN_PW@@|$(cat admin_pw.txt)|g" -e "s|@@USER_PW@@|$(cat user_pw.txt)|g" \
        "$HERE/autounattend.xml" > setupcd/autounattend.xml
    cp "$HERE/firstboot.ps1" setupcd/firstboot.ps1
    cp lab_key.pub setupcd/lab_key.pub
    cp user_pw.txt setupcd/user_pw.txt
    genisoimage -quiet -J -r -V KSETUP -o setup.iso setupcd
    rm -f "$DISK"; qemu-img create -q -f qcow2 "$DISK" 80G
    qemu_run \
        -drive file=win11.iso,if=none,id=cd0,media=cdrom,readonly=on -device ide-cd,drive=cd0,bus=ahci.1,bootindex=0 \
        -drive file=setup.iso,if=none,id=cd1,media=cdrom,readonly=on -device ide-cd,drive=cd1,bus=ahci.2
    # The Windows CD asks "Press any key to boot from CD" when the disk is bootable; tap a key early.
    for _ in $(seq 1 15); do mon 'sendkey ret'; sleep 1; done
    echo "installing (VNC 127.0.0.1:59$(printf %02d "$VNC_DISPLAY")); waiting for first boot to finish..."
    deadline=$(( $(date +%s) + ${INSTALL_TIMEOUT:-5400} ))
    until ssh "${ssh_opts[@]}" labadmin@127.0.0.1 'Test-Path C:\kestrel-lab\firstboot.done' 2>/dev/null | grep -q True; do
        running || { echo "qemu exited during install" >&2; exit 1; }
        [ "$(date +%s)" -lt "$deadline" ] || { echo "install timed out" >&2; exit 1; }
        sleep 30
    done
    echo "first boot done; letting the reboot settle"
    sleep 90
    "$SELF" wait-ssh 600
    "$SELF" stop
    # Re-launch without the install media from now on.
    qemu-img snapshot -c clean "$DISK"
    echo "snapshot 'clean' created"
    ;;
start)
    running && { echo "already running"; exit 0; }
    qemu_run
    echo "started (ssh 127.0.0.1:$SSH_PORT, VNC :$VNC_DISPLAY)"
    ;;
stop)
    running || { echo "not running"; exit 0; }
    mon 'system_powerdown'
    for _ in $(seq 1 90); do running || break; sleep 1; done
    if running; then kill "$(cat "$PIDF")"; sleep 2; fi
    rm -f "$PIDF"; echo stopped
    ;;
snapshot) running && { echo "stop the VM first" >&2; exit 1; }; qemu-img snapshot -c "$1" "$DISK"; qemu-img snapshot -l "$DISK" ;;
revert)   running && { echo "stop the VM first" >&2; exit 1; }; qemu-img snapshot -a "$1" "$DISK"; echo "reverted to $1" ;;
snapshots) qemu-img snapshot -l "$DISK" ;;
ssh)      exec ssh "${ssh_opts[@]}" labadmin@127.0.0.1 "$@" ;;
put)      scp -q -i "$KVM_DIR/lab_key" -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$1" "labadmin@127.0.0.1:$2" ;;
get)      scp -q -i "$KVM_DIR/lab_key" -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "labadmin@127.0.0.1:$1" "$2" ;;
screenshot)
    out=$(readlink -f "$1"); mon "screendump $out -f png"; sleep 1; ls -la "$out" ;;
wait-ssh)
    t=${1:-300}; end=$(( $(date +%s) + t ))
    until ssh "${ssh_opts[@]}" labadmin@127.0.0.1 'echo ok' 2>/dev/null | grep -q ok; do
        [ "$(date +%s)" -lt "$end" ] || { echo "ssh not reachable" >&2; exit 1; }
        sleep 5
    done; echo "ssh ok" ;;
*) sed -n '2,20p' "$SELF" ;;
esac
