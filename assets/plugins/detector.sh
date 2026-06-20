#!/bin/sh
input=$(cat)
case "$input" in
  *BADSTRING*) echo '{"verdicts":[{"signature":"Custom.BadString","level":"malicious","score":0.95,"detail":"third-party rule matched"}]}' ;;
  *) echo '{"verdicts":[]}' ;;
esac
