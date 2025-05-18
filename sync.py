#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from lib import ssh, scp

target = "debian"
target_dir = "~/xdp-test"

scp(target, "./Makefile", f"{target_dir}/");
scp(target, "xdp_copy_tail_call.c", f"{target_dir}/");

ssh(target, f"""#!/bin/bash
cd {target_dir}
make clean
make
echo "All done"
""")