#!/bin/bash
###
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2018-2024 SCANOSS.COM
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
###

# Simulate the ldb CLI
if [ "$1" == "-h" ] || [ "$2" == "-h" ] || [ "$1" == "-help" ] || [ "$2" == "-help" ] ; then
  echo "SCANOSS ldb simulator help"
  echo " command options..."
  exit 0
fi

# Simulate getting pivot table
if [ "$1" == "-f" ] && [ "$2" != "" ] && [[ $2 =~ pivot.txt ]] ; then
  echo "7c110b4501c727f42f13fd616e2af522,b9e4d7a54ff7267c285e266b5701de3a"
  echo "7c110b4501c727f42f13fd616e2af522,c0cc0cbd95f0f20cb95115b46e923482"
  echo "7c110b4501c727f42f13fd616e2af522,264a6f968bff7af75cd740eb6b646208"
  exit 0
fi

# Simulate getting crypto table
if [ "$1" == "-f" ] && [ "$2" != "" ] && [[ $2 =~ crypto.txt ]] ; then
  echo "264a6f968bff7af75cd740eb6b646208,SHAx,512"
  echo "264a6f968bff7af75cd740eb6b646208,SHA1,128"
  echo "264a6f968bff7af75cd740eb6b646208,shax,512"
  echo "264a6f968bff7af75cd740eb6b646208,sha1,128"
  echo "b9e4d7a54ff7267c285e266b5701de3a,ASN1,256"
  echo "c0cc0cbd95f0f20cb95115b46e923482,des,168"
  exit 0
fi

# Unknown command option, respond with error
echo "Unknown command option: $*"
exit 1
