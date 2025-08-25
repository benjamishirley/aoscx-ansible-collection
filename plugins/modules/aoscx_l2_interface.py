#!/usr/bin/python
# -*- coding: utf-8 -*-

# (C) Copyright 2019-2023 Hewlett Packard Enterprise Development LP.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import json
from collections.abc import Iterable
from ansible.module_utils.basic import AnsibleModule
from urllib.parse import quote_plus

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = """
---
module: aoscx_l2_interface
version_added: "2.8.0"
short_description: >
  Create or Update or Delete Layer2 Interface configuration on AOS-CX.
description: >
  This modules provides configuration management of Layer2 Interfaces on AOS-CX
  devices, including Port Security features. For platform 8360, Port Security
  is supported from REST v10.09 upwards.
author: Aruba Networks (@ArubaNetworks)
options:
  interface:
    description: >
      Interface name, should be in the format chassis/slot/port, i.e. 1/2/3,
      1/1/32. Please note, if the interface is a Layer3 interface in the
      existing configuration and the user wants to change the interface to be
      Layer2, the user must delete the L3 interface then recreate the interface
      as a Layer2.
    type: str
    required: true
  description:
    description: Description of interface.
    type: str
    required: false
  vlan_mode:
    description: VLAN mode on interface, access or trunk.
    choices:
      - access
      - trunk
    required: false
    type: str
  vlan_access:
    description: Access VLAN ID, vlan_mode must be set to access.
    required: false
    type: str
  vlan_trunks:
    description: List of trunk VLAN IDs, vlan_mode must be set to trunk.
    required: false
    type: list
    elements: str
  trunk_allowed_all:
    description: >
      Flag for vlan trunk allowed all on L2 interface, vlan_mode must be set to
      trunk.
    required: false
    type: bool
  native_vlan_id:
    description: VLAN trunk native VLAN ID, vlan_mode must be set to trunk.
    required: false
    type: str
  native_vlan_tag:
    description: >
      Flag for accepting only tagged packets on VLAN trunk native, vlan_mode
      must be set to trunk.
    required: false
    type: bool
  interface_qos_schedule_profile:
    description: >
      Attaching existing QoS schedule profile to interface. *This parameter is
      deprecated and will be removed in a future version.
    type: dict
    required: false
  interface_qos_rate:
    description: >
      The rate limit value configured for broadcast/multicast/unknown unicast
      traffic. Dictionary should have the format <type_of_traffic>: <speed>.
      e.g. unknown-unicast: 100pps
           broadcast: 200kbps
           multicast: 200pps
    type: dict
    required: false
  state:
    description: Create, Update, or Delete Layer2 Interface.
    choices:
      - create
      - update
      - delete
    default: create
    required: false
    type: str
  port_security_enable:
    description: Enable port security in this interface (aoscx connection).
    type: bool
    required: false
  port_security_client_limit:
    description: >
      Maximum amount of MACs allowed in the interface (aoscx connection). Only
      valid when port_security is enabled.
    type: int
    required: false
  port_security_sticky_learning:
    description: >
      Enable sticky MAC learning (aoscx connection). Only valid when
      port_security is enabled.
    type: bool
    required: false
  port_security_macs:
    description: >
      List of allowed MAC addresses (aoscx connection). Only valid when
      port_security is enabled.
    type: list
    elements: str
    required: false
  port_security_sticky_macs:
    description: >
      Configure the sticky MAC addresses for the interface (aoscx connection).
      Only valid when port_security is enabled.
    type: list
    required: false
    elements: dict
    suboptions:
      mac:
        description: a mac address.
        type: str
        required: true
      vlans:
        description: a list of VLAN IDs.
        type: list
        elements: int
        required: true
  port_security_violation_action:
    description: >
      Action to perform when a violation is detected (aoscx connection). Only
      valid when port_security is enabled.
    type: str
    choices:
      - notify
      - shutdown
    required: false
  port_security_recovery_time:
    description: >
      Time in seconds to wait for recovery after a violation (aoscx
      connection). Only valid when port_security is enabled.
    type: int
    required: false
"""

EXAMPLES = """
- name: Configure Interface 1/1/13 - set allowed MAC address
  aoscx_l2_interface:
    name: 1/1/13
    port_security_enable: true
    port_security_macs:
      - AA:BB:CC:DD:EE:FF

- name: >
    Configure Interface 1/1/13 - retain an allowed mac address by changing its
    setting to sticky mac.
  aoscx_l2_interface:
    name: 1/1/13
    port_security_enable: true
    port_security_sticky_learning: true
    port_security_sticky_macs:
      - mac: AA:BB:CC:DD:EE:FF
        vlans:
          - 1
          - 2
          - 3

- name: >
    Configure Interface 1/1/13 - retain an allowed mac address by changing its
    setting to sticky mac.
  aoscx_l2_interface:
    name: 1/1/13
    port_security_enable: true
    port_security_sticky_learning: true
    port_security_sticky_macs:
      - mac: AA:BB:CC:DD:EE:FF
        vlans: []

- name: >
    Configure Interface 1/1/13 - set intrusion action to disable the interface
    if it identifies a MAC address that is not on the allow list.
  aoscx_l2_interface:
    name: 1/1/13
    port_security_enable: true
    port_security_violation_action: shutdown
    port_security_recovery_time: 60

- name: >
    Configure Interface 1/1/13 - set port security to dynamically add the first
    8 addresses it sees to the allowed MAC address list.
  aoscx_l2_interface:
    name: 1/1/13
    port_security_enable: true
    port_security_client_limit: 8
    port_security_sticky_learning: true

- name: >
    Configure Interface 1/1/3 - enable port security for a total of 10 MAC
    addresses with sticky MAC learning, and two user set MAC addresses.
  aoscx_l2_interface:
    interface: 1/1/3
    port_security_enable: true
    port_security_client_limit: 10
    port_security_sticky_learning: true
    port_security_macs:
      - 11:22:33:44:55:66
      - AA:BB:CC:DD:EE:FF

- name: >
    Configure Interface 1/1/13 - remove allowed MAC address AA:BB:CC:DD:EE:FF
  aoscx_l2_interface:
    name: 1/1/13
    port_security_enable: true
    port_security_macs:
      - AA:BB:CC:DD:EE:FF
    state: delete

- name: Configure Interface 1/1/13 - delete configuration of client limit.
  aoscx_l2_interface:
    name: 1/1/13
    port_security_enable: true
    port_security_client_limit: 2
    state: delete

- name: >
    Configure Interface 1/1/13 - delete configuration of recovery time.
  aoscx_l2_interface:
    name: 1/1/13
    port_security_enable: true
    port_security_recovery_time: 60
    state: delete

- name: Configure Interface 1/1/13 - disable port security.
  aoscx_l2_interface:
    name: 1/1/13
    port_security_enable: false

- name: >
    Configure Interface 1/1/2 - enable interface and vsx-sync features
    IMPORTANT NOTE: the aoscx_interface module is needed to enable the
    interface and set the VSX features to be synced.
  aoscx_interface:
    name: 1/1/2
    enabled: true
    vsx_sync:
      - acl
      - irdp
      - qos
      - rate_limits
      - vlan
      - vsx_virtual

- name: Configure Interface 1/1/3 - vlan trunk allowed all
  aoscx_l2_interface:
    interface: 1/1/3
    vlan_mode: trunk
    trunk_allowed_all: true

- name: Delete Interface 1/1/3
  aoscx_l2_interface:
    interface: 1/1/3
    state: delete

- name: Configure Interface 1/1/1 - vlan trunk allowed 200
  aoscx_l2_interface:
    interface: 1/1/1
    vlan_mode: trunk
    vlan_trunks: 200

- name: Configure Interface 1/1/1 - vlan trunk allowed 200,300
  aoscx_l2_interface:
    interface: 1/1/1
    vlan_mode: trunk
    vlan_trunks:
      - 200
      - 300

- name: >
    Configure Interface 1/1/1 - vlan trunks allowed 200, 300, vlan trunk native
    200.
  aoscx_l2_interface:
    interface: 1/1/3
    vlan_mode: trunk
    vlan_trunks:
      - 200
      - 300
    native_vlan_id: '200'

- name: Configure Interface 1/1/4 - vlan access 200
  aoscx_l2_interface:
    interface: 1/1/4
    vlan_mode: access
    vlan_access: '200'
- name: >
    Configure Interface 1/1/5 - vlan trunk allowed all, vlan trunk native 200
    tag.
  aoscx_l2_interface:
    interface: 1/1/5
    vlan_mode: trunk
    trunk_allowed_all: true
    native_vlan_id: '200'
    native_vlan_tag: true

- name: >
    Configure Interface 1/1/6 - vlan trunk allowed all, vlan trunk native 200.
  aoscx_l2_interface:
    interface: 1/1/6
    vlan_mode: trunk
    trunk_allowed_all: true
    native_vlan_id: '200'
"""

RETURN = r""" # """


from ansible_collections.arubanetworks.aoscx.plugins.module_utils.aoscx_pyaoscx import (  # NOQA
    get_pyaoscx_session,
)





############## Helpers

def serialize_value(value, key=None):

    # if key == "port_access_onboarding_precedence":
    #     # Dict wie {"1": "aaa", "2": "device-profile"} → Liste
    #     if isinstance(value, dict):
    #         # Sortiert nach numerischem Schlüssel
    #         return [value[k] for k in sorted(value.keys(), key=int)]
    #     return value  # Wenn bereits Liste

    if key == "vlan_mode":
        vlan_mode_map = {
            "native-untagged": "trunk",
            "native-tagged": "trunk"
        }
        return vlan_mode_map.get(value, value)

    if isinstance(value, dict):
        # Recursively serialize dict values
        return {k: serialize_value(v, k) for k, v in value.items()}

    if isinstance(value, list):
        return [serialize_value(v, key) for v in value]

    if hasattr(value, "vlan_id"):
        return str(value.vlan_id)
    if hasattr(value, "id"):
        return str(value.id)

    if callable(value):
        return None

    return value



def _normalize_subset(d):
    # keep only keys with non-None values, serialize simple things
    return {k: serialize_value(v, k) for k, v in (d or {}).items() if v is not None}

def _list_auth_subresources(session, ifname):
    path = f"system/interfaces/{quote_plus(ifname)}/port_access_auth_configurations"
    resp = session.request("GET", path)
    try:
        data = json.loads(resp.text) if resp is not None else {}
    except Exception:
        data = {}
    return resp.status_code, data

def _ensure_auth_subresource(session, ifname, method):
    # returns (ok, created)
    status, data = _list_auth_subresources(session, ifname)
    if status // 100 == 2 and method in (data or {}):
        return True, False  # ok, not created

    create_path = f"system/interfaces/{quote_plus(ifname)}/port_access_auth_configurations"
    body = {"authentication_method": method}
    r = session.request("POST", create_path, data=json.dumps(body))
    if r.status_code in (200, 201):
        return True, True  # ok, created

    if r.status_code == 500:
        status2, data2 = _list_auth_subresources(session, ifname)
        if status2 // 100 == 2 and method in (data2 or {}):
            # war schon da → ok, not created
            return True, False
    return False, False  # failed

def _get_auth_config(session, ifname, method):
    # Read current subresource config to build a precise diff
    path = f"system/interfaces/{quote_plus(ifname)}/port_access_auth_configurations/{method}"
    resp = session.request("GET", path)
    if resp.status_code // 100 == 2 and resp.text:
        try:
            return json.loads(resp.text)
        except Exception:
            return {}
    return {}




def get_argument_spec():
    module_args = {
        "state": {
            "type": "str",
            "default": "create",
            "choices": ["create", "delete", "update"],
        },
        "interface": {
            "type": "str",
            "required": True,
        },
        "description": {
            "type": "str",
            "required": False,
            "default": None,
        },
        "vlan_mode": {
            "type": "str",
            "default": None,
            "required": False,
            "choices": ["access", "trunk"],
        },
        "vlan_access": {
            "type": "str",
            "default": None,
            "required": False,
        },
        "vlan_trunks": {
            "type": "list",
            "elements": "str",
            "default": None,
            "required": False,
        },
        "trunk_allowed_all": {
            "type": "bool",
            "default": None,
            "required": False,
        },
        "native_vlan_id": {
            "type": "str",
            "default": None,
            "required": False,
        },
        "native_vlan_tag": {
            "type": "bool",
            "default": None,
            "required": False,
        },
        "interface_qos_schedule_profile": {
            "type": "dict",
            "default": None,
            "required": False,
        },
        "interface_qos_rate": {
            "type": "dict",
            "default": None,
            "required": False,
        },
        "port_security_enable": {
            "type": "bool",
            "required": False,
            "default": None,
        },
        "port_security_client_limit": {
            "type": "int",
            "required": False,
            "default": None,
        },
        "port_security_sticky_learning": {
            "type": "bool",
            "required": False,
            "default": None,
        },
        "port_security_macs": {
            "type": "list",
            "elements": "str",
            "required": False,
            "default": None,
        },
        "port_security_sticky_macs": {
            "type": "list",
            "elements": "dict",
            "required": False,
            "default": None,
            "options": {
                "mac": {"type": "str", "required": True},
                "vlans": {
                    "type": "list",
                    "elements": "int",
                    "required": True,
                },
            },
        },
        "port_security_violation_action": {
            "type": "str",
            "required": False,
            "default": None,
            "choices": ["notify", "shutdown"],
        },
        "port_security_recovery_time": {
            "type": "int",
            "required": False,
            "default": None,
        },

        # New Specs

        "port_access_onboarding_precedence": {
            "type": "dict",
            "default": None,
            "required": False,
        },

        "enforce_vlan_trunks": {
            "type": "bool",
            "default": False,
            "required": False,
        },
        
        ## SL Port-Access Required Settings
        "port_access_allow_flood_traffic": {
            "type": "bool",
            "required": False,
            "default": None,
            
        },
        "port_access_client_limit": {
            "type": "int",
            "required": False,
            "default": None,
        },

        # port-access subresources
        "mac_auth": {
            "type": "dict",
            "required": False,
            "default": None,
            "options": {
                "auth_enable": {"type": "bool"},
                "cached_reauth_enable": {"type": "bool"},
                "cached_reauth_period": {"type": "int"},
                "canned_eap_success_enable": {"type": "bool"},
                "discovery_period": {"type": "int"},
                "eapol_timeout": {"type": "int"},
                "initial_auth_response_timeout": {"type": "int"},
                "macsec_enable": {"type": "bool"},
                "max_requests": {"type": "int"},
                "max_retries": {"type": "int"},
                "mka_cak_length": {"type": "str"},  # "16" | "32"
                "quiet_period": {"type": "int"},
                "radius_server_group": {"type": "str"},
                "reauth_enable": {"type": "bool"},
                "reauth_period": {"type": "int"},
            },
        },
        "dot1x": {
            "type": "dict",
            "required": False,
            "default": None,
            "options": {
                "auth_enable": {"type": "bool"},
                "reauth_enable": {"type": "bool"},
                "reauth_period": {"type": "int"},
                "quiet_period": {"type": "int"},
                "max_retries": {"type": "int"},
                "max_requests": {"type": "int"},
                "eapol_timeout": {"type": "int"},
                "initial_auth_response_timeout": {"type": "int"},
                "radius_server_group": {"type": "str"},
                "cached_reauth_enable": {"type": "bool"},
                "cached_reauth_period": {"type": "int"},
                "canned_eap_success_enable": {"type": "bool"},
                "discovery_period": {"type": "int"},
                "macsec_enable": {"type": "bool"},
                "mka_cak_length": {"type": "str"},
            },
        },

    }
    return module_args


IGNORED_DIFF_KEYS = ["state", "interface", "enforce_vlan_trunks"]



def main():
    ansible_module = AnsibleModule(
        argument_spec=get_argument_spec(), supports_check_mode=True
    )

    result = dict(changed=False, diff={})

    interface_name = ansible_module.params["interface"]
    description = ansible_module.params["description"]
    vlan_mode = ansible_module.params["vlan_mode"]
    vlan_access = ansible_module.params["vlan_access"]
    
    ### initial change vars
    changed_l2 = False
    changed_auth = False
    changed_portsec = False
    changed_precedence = False
        

    # Für den Vergleich im check mode wird hier sortiert!!
    vlan_trunks = ansible_module.params.get("vlan_trunks")
    if vlan_trunks:
        ansible_module.params["vlan_trunks"] = sorted(
            set(vlan_trunks), key=int)

    enforce_vlan_trunks = ansible_module.params.get("enforce_vlan_trunks")

    trunk_allowed_all = ansible_module.params["trunk_allowed_all"]
    native_vlan_id = ansible_module.params["native_vlan_id"]
    native_vlan_tag = ansible_module.params["native_vlan_tag"]
    state = ansible_module.params["state"]
    port_security_enable = ansible_module.params["port_security_enable"]
    port_security_client_limit = ansible_module.params[
        "port_security_client_limit"
    ]
    port_security_sticky_learning = ansible_module.params[
        "port_security_sticky_learning"
    ]
    port_security_macs = ansible_module.params["port_security_macs"]
    port_security_sticky_macs = ansible_module.params[
        "port_security_sticky_macs"
    ]
    port_security_violation_action = ansible_module.params[
        "port_security_violation_action"
    ]
    port_security_recovery_time = ansible_module.params[
        "port_security_recovery_time"
    ]

    port_access_onboarding_precedence = ansible_module.params[
        "port_access_onboarding_precedence"
    ]
    
    port_access_allow_flood_traffic = ansible_module.params[
        "port_access_allow_flood_traffic"
    ]

    port_access_client_limit = ansible_module.params[
        "port_access_client_limit"
    ]


    precedence_check = ansible_module.params["port_access_onboarding_precedence"]
    if precedence_check:
        VALID_VALUES = {"device-profile", "aaa"}
        invalid = set(precedence_check.values()) - VALID_VALUES
        if invalid:
            ansible_module.fail_json(
                msg=f"port_access_onboarding_precedence - invalid values: {sorted(invalid)} – allowed: {sorted(VALID_VALUES)}")

    try:
        from pyaoscx.device import Device
        from pyaoscx.utils import util as utils
    except Exception as e:
        ansible_module.fail_json(msg=str(e))

    try:
        session = get_pyaoscx_session(ansible_module)
        session.s.verify = False   
    except Exception as e:
        ansible_module.fail_json(
            msg="Could not get PYAOSCX Session: {0}".format(str(e))
        )

    device = Device(session)
    interface = device.interface(interface_name)
    modified = interface.modified

    if (
        state == "delete"
        and port_security_enable is None
        and vlan_trunks is None
    ):
        is_special_type = interface.type in [
            "lag",
            "loopback",
            "tunnel",
            "vlan",
            "vxlan",
        ]
        if is_special_type:
            # report only if created before this run
            interface.delete()
            result["changed"] = not modified
        else:
            # physical interfaces cannot be deleted, in this case default
            # values are loaded
            prev_intf_attrs = utils.get_attrs(
                interface, interface.config_attrs
            )
            interface.delete()
            Interface = session.api.get_module_class(session, "Interface")
            interface = Interface(session, interface_name)
            interface.get()
            curr_intf_attrs = utils.get_attrs(
                interface, interface.config_attrs
            )
            # interfaces list members in dictionary are pointers to Interface
            # objects, so they are converted to str value to avoid false
            # negatives
            prev_intf_attrs["interfaces"] = list(
                map(str, prev_intf_attrs["interfaces"])
            )
            curr_intf_attrs["interfaces"] = list(
                map(str, curr_intf_attrs["interfaces"])
            )

            # need to compare if there are any changes after deleting
            result["changed"] = prev_intf_attrs != curr_intf_attrs
        ansible_module.exit_json(**result)
    vlan_tag = None
    if vlan_access is not None:
        vlan_tag = vlan_access
    elif native_vlan_id is not None:
        vlan_tag = native_vlan_id

    if isinstance(vlan_tag, str):
        vlan_tag = int(vlan_tag)

    # if interface.was_modified():
    #     result["changed"] = True

    if vlan_trunks:
        if enforce_vlan_trunks:
            # Hartes Syncing: Trunks exakt so setzen, wie angegeben
            vlan_trunks = sorted(set(vlan_trunks), key=int)
        else:
            # Weiches Merge-Verhalten
            if interface.vlan_mode in ["native-tagged", "native-untagged"]:
                if state == "delete":
                    Vlan = session.api.get_module_class(session, "Vlan")
                    orig_vlan_set = set(
                        [str(v.id) for v in interface.vlan_trunks]
                        if interface.vlan_trunks
                        else [str(v.id) for v in Vlan.get_all(session)]
                    )
                    new_vlan_set = orig_vlan_set - set(vlan_trunks)
                else:
                    orig_vlan_set = set(
                        [str(v.id) for v in interface.vlan_trunks]
                        if interface.vlan_trunks
                        else []
                    )
                    new_vlan_set = orig_vlan_set | set(vlan_trunks)
                vlan_trunks = list(new_vlan_set)
                trunk_allowed_all = vlan_trunks == []
            elif state == "delete":
                ansible_module.fail_json(
                    msg="Deleting VLANs on non-trunk interface {0}".format(
                        interface.name
                    )
                )


    # Check Mode
    if ansible_module.check_mode:
        config_diff = False
        diff = {}

        GENERIC_SKIP = set(IGNORED_DIFF_KEYS) | {"mac_auth", "dot1x"}

        # 1) Generic Fields (wie gehabt)
        for key, desired_value in ansible_module.params.items():
            if key in GENERIC_SKIP or desired_value is None:
                continue
            current_value = getattr(interface, key, None)
            current_serialized = serialize_value(current_value, key)
            desired_serialized = serialize_value(desired_value, key)
            if current_serialized != desired_serialized:
                config_diff = True
                diff[key] = {
                    "current": current_serialized,
                    "desired": desired_serialized,
                }

        # 2) Auth-Subresources (mac-auth / dot1x), ohne POSTs im Check-Mode
        #    -> erst Liste lesen, dann ggf. Detail lesen, nur gewünschte Keys vergleichen
        for method, param_key in (("mac-auth", "mac_auth"), ("dot1x", "dot1x")):
            desired = ansible_module.params.get(param_key)
            if not desired:
                continue

            desired_norm = _normalize_subset(desired)

            # Existiert das Sub-Resource?
            status, listing = _list_auth_subresources(session, interface_name)
            exists = (status // 100 == 2) and (method in (listing or {}))

            if not exists:
                # Würden wir anlegen -> Änderung signalisieren
                config_diff = True
                diff[param_key] = {"current": {}, "desired": desired_norm}
                continue

            # Sub-Resource existiert -> Detail laden und nur gewünschte Keys vergleichen
            current_full = _get_auth_config(session, interface_name, method)
            current_subset = {k: serialize_value(current_full.get(k), k)
                            for k in desired_norm.keys()}

            if current_subset != desired_norm:
                config_diff = True
                diff[param_key] = {
                    "current": current_subset,
                    "desired": desired_norm,
                }

        result["changed"] = config_diff
        result["diff"] = diff
        ansible_module.exit_json(**result)
        
    else:
        # only if not check mode
        changed_l2 = bool(interface.configure_l2(
            description=description,
            vlan_mode=vlan_mode,
            vlan_tag=vlan_tag,
            vlan_ids_list=vlan_trunks,
            trunk_allowed_all=trunk_allowed_all,
            native_vlan_tag=native_vlan_tag,
            port_access_allow_flood_traffic=port_access_allow_flood_traffic,
            port_access_client_limit=port_access_client_limit
        ))



    if port_access_onboarding_precedence:
        if ansible_module.check_mode:
            if interface.port_access_onboarding_precedence != port_access_onboarding_precedence:
                result["changed"] = True
        else:
            if interface.port_access_onboarding_precedence != port_access_onboarding_precedence:
                interface.port_access_onboarding_precedence = port_access_onboarding_precedence
                applied = interface.apply()
                changed_precedence = bool(applied)



    # --- apply mac-auth / dot1x if provided (idempotent) ---


    for method, param_key, setter in (
        ("mac-auth", "mac_auth", "set_mac_auth"),
        ("dot1x",   "dot1x",   "set_dot1x"),
    ):
        desired = ansible_module.params.get(param_key)
        if not desired:
            continue

        # ensure subresource exists
        ok, _created = _ensure_auth_subresource(session, interface_name, method)
        if not ok:
            ansible_module.fail_json(
                msg=f"Failed to create auth subresource '{method}' on {interface_name}"
            )

        # compare current vs desired subset
        desired_norm = _normalize_subset(desired)
        current_full = _get_auth_config(session, interface_name, method)
        current_subset = {k: serialize_value(current_full.get(k), k) for k in desired_norm.keys()}

        if current_subset != desired_norm:
            # only patch when delta exists
            try:
                applied = getattr(interface, setter)(**desired_norm)
            except Exception as exc:
                ansible_module.fail_json(msg=f"Failed to set {method} config: {exc}")
            changed_auth |= bool(applied)
        # else: no-op → do not mark changed




    # --- Port Security ---
    changed_portsec = False

    if port_security_enable is not None and not port_security_enable:
        if ansible_module.check_mode:
            result["changed"] = True
        else:
            changed_portsec |= bool(interface.port_security_disable())

    if port_security_enable or (
        hasattr(interface, "port_security")
        and interface.port_security["enable"]
    ):
        port_sec_kw = {}
        if state == "delete":
            if port_security_client_limit:
                port_sec_kw["client_limit"] = 1
            if port_security_sticky_learning is not None:
                port_sec_kw["sticky_mac_learning"] = False
            if port_security_macs:
                for mac in port_security_macs:
                    mac = mac.upper()
                    sw_static_macs = interface.port_security_static_client_mac_addr
                    if mac in sw_static_macs:
                        if ansible_module.check_mode:
                            result["changed"] = True
                        else:
                            sw_static_macs.remove(mac)
                            changed_portsec |= bool(interface.apply())
                    else:
                        ansible_module.fail_json(
                            msg="MAC address {0} is not configured".format(mac)
                        )
            if port_security_sticky_macs:
                for sticky_mac in port_security_sticky_macs:
                    mac = sticky_mac["mac"]
                    sw_sticky_macs = interface.port_security_static_sticky_client_mac_addr
                    sw_sticky_mac_vlans = sw_sticky_macs.get(mac, [])
                    if mac in sw_sticky_macs:
                        changed_here = False
                        for vlan in sticky_mac["vlans"]:
                            if vlan in sw_sticky_mac_vlans:
                                if ansible_module.check_mode:
                                    result["changed"] = True
                                    changed_here = True
                                else:
                                    sw_sticky_mac_vlans.remove(vlan)
                                    changed_here = True
                        if not ansible_module.check_mode:
                            if sw_sticky_mac_vlans == []:
                                del sw_sticky_macs[mac]
                            if changed_here:
                                changed_portsec |= bool(interface.apply())
                    else:
                        ansible_module.fail_json(
                            msg="MAC address {0} is not configured".format(mac)
                        )
            if port_security_violation_action:
                port_sec_kw["violation_action"] = "notify"
            if port_security_recovery_time:
                port_sec_kw["violation_recovery_time"] = 10
        else:
            if port_security_client_limit:
                port_sec_kw["client_limit"] = port_security_client_limit
            if port_security_sticky_learning is not None:
                port_sec_kw["sticky_mac_learning"] = port_security_sticky_learning
            if port_security_macs:
                port_sec_kw["allowed_mac_addr"] = port_security_macs
            if port_security_sticky_macs:
                converted_sticky_macs = {el["mac"]: el["vlans"] for el in port_security_sticky_macs}
                port_sec_kw["allowed_sticky_mac_addr"] = converted_sticky_macs
            if port_security_violation_action:
                port_sec_kw["violation_action"] = port_security_violation_action
            if port_security_recovery_time:
                port_sec_kw["violation_recovery_time"] = port_security_recovery_time

        _result = False
        if not ansible_module.check_mode:
            try:
                _result = interface.port_security_enable(**port_sec_kw)
            except Exception as exc:
                ansible_module.fail_json(msg=str(exc))
            changed_portsec |= bool(_result)
        else:
            # Im Check-Mode nur signalisieren, DASS es Änderungen gäbe,
            # wenn es überhaupt etwas zu patchen gäbe:
            if port_sec_kw:
                result["changed"] = True

    if changed_l2 or changed_auth or changed_portsec or changed_precedence:
        result["changed"] = True

    ansible_module.exit_json(**result)


if __name__ == "__main__":
    main()
