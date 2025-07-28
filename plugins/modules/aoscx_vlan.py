#!/usr/bin/python
# -*- coding: utf-8 -*-

# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = """
---
module: aoscx_vlan
version_added: "2.8.0"
short_description: Create or Delete VLAN configuration on AOS-CX
description: >
  This modules provides configuration management of VLANs on AOS-CX devices.
author: Aruba Networks (@ArubaNetworks)
options:
  vlan_id:
    description: >
      The ID of this VLAN. Non-internal VLANs must have an 'id' between 1 and
      4094 to be effectively instantiated.
    required: true
    type: int
  name:
    description: VLAN name
    required: false
    type: str
  description:
    description: VLAN description
    required: false
    type: str
  admin_state:
    description: The Admin State of the VLAN, options are 'up' and 'down'.
    required: false
    choices:
      - up
      - down
    type: str
  acl_name:
    description: Name of the ACL being applied or removed from the VLAN.
    required: false
    type: str
  acl_type:
    description: Type of ACL being applied or removed from the VLAN.
    choices:
      - ipv4
      - ipv6
      - mac
    required: false
    type: str
  acl_direction:
    description: Direction for which the ACL is to be applied or removed.
    choices:
      - in
      - out
    required: false
    type: str
  voice:
    description: Enable Voice VLAN
    required: false
    type: bool
  vsx_sync:
    description: Enable vsx_sync (Only for VSX device)
    required: false
    type: bool
  ip_igmp_snooping:
    description: Enable IP IGMP Snooping
    required: false
    type: bool
  state:
    description: Create or update or delete the VLAN.
    required: false
    choices:
      - create
      - update
      - delete
    default: create
    type: str
"""

EXAMPLES = """
- name: Create VLAN 200 with description
  aoscx_vlan:
    vlan_id: 200
    description: This is VLAN 200

- name: Create VLAN 300 with description and name
  aoscx_vlan:
    vlan_id: 300
    name: UPLINK_VLAN
    description: This is VLAN 300

- name: Set ACL test_acl type ipv6 in
  aoscx_vlan:
    vlan_id: 300
    acl_name: test_acl
    acl_type: ipv6
    acl_direction: in

- name: Remove ACL test_acl type ipv6 in
  aoscx_vlan:
    vlan_id: 300
    acl_name: test_acl
    acl_type: ipv6
    acl_direction: in
    state: delete

- name: Create VLAN 400 with name, voice, vsx_sync and ip igmp snooping
  aoscx_vlan:
    vlan_id: 400
    name: VOICE_VLAN
    voice: True
    vsx_sync: True
    ip_igmp_snooping: True

- name: Delete VLAN 300
  aoscx_vlan:
    vlan_id: 300
    state: delete
"""

RETURN = r""" # """

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.arubanetworks.aoscx.plugins.module_utils.aoscx_pyaoscx import (
    get_pyaoscx_session,
)

def get_argument_spec():
    return {
        "vlan_id": {"type": "int", "required": True},
        "name": {"type": "str", "default": None},
        "description": {"type": "str", "default": None},
        "admin_state": {"type": "str", "default": None, "choices": ["up", "down"]},
        "acl_name": {"type": "str", "required": False},
        "acl_type": {"type": "str", "required": False, "choices": ["ipv4", "ipv6", "mac"]},
        "acl_direction": {"type": "str", "choices": ["in", "out"]},
        "voice": {"type": "bool", "required": False},
        "vsx_sync": {"type": "bool", "required": False},
        "ip_igmp_snooping": {"type": "bool", "required": False},
        "state": {"type": "str", "default": "create", "choices": ["create", "delete", "update"]},
    }

def vlan_would_change(vlan, params):
    changes = []
    if params["name"] and vlan.name != params["name"]:
        changes.append("name would change")
    if params["description"] and vlan.description != params["description"]:
        changes.append("description would change")
    if params["admin_state"] and hasattr(vlan, "admin") and vlan.admin != params["admin_state"]:
        changes.append("admin_state would change")
    if params["voice"] is not None and vlan.voice != params["voice"]:
        changes.append("voice flag would change")
    if params["vsx_sync"] is not None:
        target = ["all_attributes_and_dependents"] if params["vsx_sync"] else []
        if vlan.vsx_sync != target:
            changes.append("vsx_sync would change")
    if params["ip_igmp_snooping"] is not None:
        igmp = vlan.mgmd_enable.get("igmp", None)
        if igmp != params["ip_igmp_snooping"]:
            changes.append("IGMP snooping would change")
    return changes


def update_vlan_attributes(vlan, params):
    modified = False

    if params["name"]:
        modified |= vlan.name != params["name"]
        vlan.name = params["name"]
    if params["description"]:
        modified |= vlan.description != params["description"]
        vlan.description = params["description"]
    if params["admin_state"] and hasattr(vlan, "admin"):
        modified |= vlan.admin != params["admin_state"]
        vlan.admin = params["admin_state"]
    if params["voice"] is not None:
        modified |= vlan.voice != params["voice"]
        vlan.voice = params["voice"]
    if params["vsx_sync"] is not None:
        target = ["all_attributes_and_dependents"] if params["vsx_sync"] else []
        modified |= vlan.vsx_sync != target
        vlan.vsx_sync = target
    if params["ip_igmp_snooping"] is not None:
        modified |= vlan.mgmd_enable.get("igmp", None) != params["ip_igmp_snooping"]
        vlan.mgmd_enable["igmp"] = params["ip_igmp_snooping"]

    return modified

def main():
    module = AnsibleModule(
        argument_spec=get_argument_spec(),
        required_together=[["acl_name", "acl_type", "acl_direction"]],
        supports_check_mode=True,
    )

    result = dict(changed=False, warnings=[])
    params = module.params

    try:
        session = get_pyaoscx_session(module)
    except Exception as e:
        module.fail_json(msg=f"Could not get PYAOSCX Session: {e}")

    Vlan = session.api.get_module_class(session, "Vlan")
    vlan = Vlan(session, params["vlan_id"], params["name"])

    try:
        vlan.get()
        exists = True
    except Exception:
        exists = False

    if module.check_mode:
        changes = []
        if params["state"] == "delete" and exists:
            changes.append("VLAN would be deleted")
        elif params["state"] == "create" and not exists:
            changes.append("VLAN would be created")
        elif params["state"] in ["create", "update"] and exists:
            changes += vlan_would_change(vlan, params)
        result["changed"] = bool(changes)
        result["simulated_changes"] = changes
        module.exit_json(**result)

    modified = False

    if params["state"] == "delete":
        if params["acl_type"]:
            vlan.clear_acl(params["acl_type"], params["acl_direction"])
            modified = True
        elif exists:
            vlan.delete()
            modified = True


    elif params["state"] == "create":
        if not exists:
            vlan.name = params["name"] or f"VLAN{params['vlan_id']}"
            vlan.create()
            modified = True
            exists = True  # für folgenden Block wichtig

        if exists:
            modified |= update_vlan_attributes(vlan, params)
            if modified:
                vlan.apply()
            if params["acl_name"]:
                modified |= vlan.set_acl(params["acl_name"], params["acl_type"], params["acl_direction"])

    elif params["state"] == "update":
        if not exists:
            module.fail_json(msg=f"VLAN {params['vlan_id']} does not exist and cannot be updated")

        modified |= update_vlan_attributes(vlan, params)
        if modified:
            vlan.apply()
        if params["acl_name"]:
            modified |= vlan.set_acl(params["acl_name"], params["acl_type"], params["acl_direction"])

    result["changed"] = modified
    module.exit_json(**result)

if __name__ == "__main__":
    main()