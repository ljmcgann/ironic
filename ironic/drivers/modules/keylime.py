# Copyright 2016 Hewlett Packard Enterprise Development Company LP.
# Copyright 2016 IBM Corp
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re
import time

from oslo_log import log

from ironic.common import exception
from ironic.common import utils
from ironic.conf import CONF
from ironic.drivers.modules import agent_client

from ironic.drivers import base

LOG = log.getLogger(__name__)

REQUIRED_PROPERTIES = {"keylime_v": "the IP address of the cloud verifier",
                       "keylime_vp": "the port of the cloud verifier",
                       "keylime_f": ("Deliver the specified plaintext to the "
                                     "provisioned agent"),
                       "keylime_allowlist": ("Specify the file path of"
                                             "an allowlist")}


APPROVED_REACTIVATE_STATES = ["Start", "Get Quote", "Get Quote (retry)",
                              "Provide V", "Provide V (retry)"]


class KeylimeSecurity(base.SecurityInterface):

    def get_properties(self):
        return {}

    def validate(self, task):

        info = task.node.driver_info or {}
        missing_info = [key for key in REQUIRED_PROPERTIES if not info.get(key)]
        if missing_info:
            raise exception.MissingParameterValue((
                "Missing the following Keylime credentials in node's"
                " driver_info: %s.") % missing_info)

    @base.clean_step(priority=120)
    def start_attestation(self, task):
        LOG.debug("Hello from Keylime interface start_attestation")
        time.sleep(60)

        verifier = task.node.driver_info.get('keylime_v')
        verifier_port = task.node.driver_info.get('keylime_vp')
        exclude = task.node.driver_info.get('keylime_exclude')
        allow = task.node.driver_info.get('keylime_allowlist')

        node = task.node

        agent_info = self.get_agent_info(node)

        updated_driver_info = node['driver_info']
        updated_driver_info.update(agent_info)
        node.update({'driver_info': updated_driver_info})

        cmd = ["keylime_tenant",
               "-c", "add",
               "-t", agent_info['keylime_t'],
               "-tp", agent_info['keylime_tp'],
               "-v", verifier,
               "-vp", str(verifier_port),
               "-u", agent_info["keylime_u"],
               "-f", exclude,
               "--allowlist", allow,
               "--exclude", exclude]


        out, err = utils.execute(*cmd)

    @base.clean_step(priority=119)
    def validate_security_status(self, task):

        LOG.debug("Hello from Keylime interface validate_security_status")
        time.sleep(60)

        verifier = task.node.driver_info.get('keylime_v')
        verifier_port = task.node.driver_info.get('keylime_vp')

        node = task.node

        cmd = ["keylime_tenant",
               "-c", "status",
               "-u", node.driver_info.get("keylime_u"),
               "-v", verifier,
               "-vp", str(verifier_port),
        ]

        out, err = utils.execute(*cmd)

        status = (re.search('Agent Status: \".*\"', out).group())[15:-1]
        LOG.debug("Keylime verifier received Agent Status " + status)


        if status != "Get Quote":
            raise exception.AttestationFailure(status=status,
                                               node=node['name'])


    @base.clean_step(priority=118)
    def unregister_node(self, task):

        LOG.debug("Hello from Keylime interface unregister_node")
        time.sleep(60)

        cmd = ["keylime_tenant",
               "-c", "delete",
               "-v", task.node.driver_info.get('keylime_v'),
               "-vp", str(task.node.driver_info.get('keylime_vp')),
               "-u", task.node.driver_info.get("keylime_u"),
               #"--no-verifier-check"
               ]

        out, err = utils.execute(*cmd)

    def get_agent_info(self, node):

        client = agent_client.AgentClient()

        try:
            result = client.get_keylime_info(node)
        except exception.IronicException as e:
            LOG.error('Failed to invoke get_keylime_info agent command '
                      'for node %(node)s. Error: %(error)s',
                      {'node': node.uuid, 'error': e})
            return

        error = result.get('faultstring')
        if error is not None:
            LOG.error('Failed to collect logs from the node %(node)s '
                      'deployment. Error: %(error)s',
                      {'node': node.uuid, 'error': error})
            return

        return {'keylime_t': result['command_result']['keylime_agent_ip'],
                'keylime_tp': result['command_result']['keylime_agent_port'],
                'keylime_u':  result['command_result']['keylime_agent_uuid']
                }

