#!/bin/bash
# Reload the mudlark-proxy service after certificate renewal
# Used as a certbot deploy hook

systemctl reload mudlark-proxy 2>/dev/null || systemctl restart mudlark-proxy
echo "MUDlark proxy reloaded with new certificates"
