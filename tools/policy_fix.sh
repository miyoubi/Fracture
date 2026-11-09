#!/system/bin/sh
# Policy fix: restore the netlink policy-capability bits and reload the
# policy in one write.  Adapted from the ghostlock-oneplus policy fix.
P=/sys/fs/selinux/policy
L=/sys/fs/selinux/load
T=/data/local/tmp/.policy.bin
LOG=/data/local/tmp/.policy_fix.log
exec >>$LOG 2>&1
echo "[*] policy fix: uid=$(id -u) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)"
cp $P $T || { echo '[!] policy copy failed'; exit 1; }
SZ=$(wc -c < $T)
[ "$SZ" -gt 20 ] || { echo "[!] policy too short ($SZ)"; exit 1; }
ID_LEN=$(dd if=$T bs=1 skip=4 count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')
CO=$((4 + 4 + ID_LEN + 4))
CFG=$(dd if=$T bs=1 skip=$CO count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')
NEW=$(( CFG | 0xC0000000 ))
if [ "$NEW" != "$CFG" ]; then
  printf '\x%02x\x%02x\x%02x\x%02x' \
    $((NEW & 0xFF)) $(((NEW>>8) & 0xFF)) $(((NEW>>16) & 0xFF)) $(((NEW>>24) & 0xFF)) \
    | dd of=$T bs=1 seek=$CO conv=notrunc 2>/dev/null
  echo "[*] policy fix: config $CFG -> $NEW at $CO"
else
  echo "[*] policy fix: config $CFG at $CO already has netlink flags"
fi
if load_policy $T 2>/dev/null; then
  echo '[+] policy loaded via load_policy'
  rm -f $T
  exit 0
fi
if cat $T > $L 2>/dev/null; then
  echo '[+] policy loaded via cat'
  rm -f $T
  exit 0
fi
echo '[!] policy load failed'
rm -f $T
exit 1
