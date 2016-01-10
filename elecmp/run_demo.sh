#!/bin/bash

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

#source $THIS_DIR/../env.sh
# ---------------- EDIT THIS ------------------
BMV2_PATH=~/bmv2
# e.g. BMV2_PATH=$THIS_DIR/../bmv2
P4C_BM_PATH=~/p4c-bmv2
# e.g P4C_BM_PATH=$THIS_DIR/../p4c-bm
# ---------------- END ------------------


P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py

SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

CLI_PATH=$BMV2_PATH/tools/runtime_CLI.py

SWITCH_NAME=elecmp

$P4C_BM_SCRIPT p4src/$SWITCH_NAME.p4 --json $SWITCH_NAME.json
sudo mn -c
sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python netbuilder.py \
    --behavioral-exe $BMV2_PATH/targets/simple_switch/simple_switch \
    --json $SWITCH_NAME.json \
    --cli $CLI_PATH
