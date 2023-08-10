#!/usr/bin/python3
# coding=utf-8

#   Copyright 2022 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Module """
from datetime import datetime

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401

from plugins.auth_core.tools import rpc_tools


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        # RPCs
        self._rpcs = [
            [self._init_auth_processor, "auth_init_auth_processor"],
        ]

    #
    # Module
    #

    def init(self):
        """ Init module """
        log.info("Initializing module")
        # Init RPCs
        for rpc_item in self._rpcs:
            self.context.rpc_manager.register_function(*rpc_item)
        # Register init auth processor
        self.context.rpc_manager.call.auth_register_auth_processor(
            "auth_init_auth_processor"
        )

    def deinit(self):  # pylint: disable=R0201
        """ De-init module """
        log.info("De-initializing module")
        # Unregister init auth processor
        self.context.rpc_manager.call.auth_unregister_auth_processor(
            "auth_init_auth_processor"
        )
        # De-init RPCs
        for rpc_item in self._rpcs:
            self.context.rpc_manager.unregister_function(*rpc_item)

    #
    # RPC
    #

    #
    # RPC: Init auth processor
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _init_auth_processor(self, auth_ctx):
        # Ensure root group present
        try:
            self.context.rpc_manager.call.auth_get_group(1)
        except:
            self.context.rpc_manager.call.auth_add_group("Root", None, 1)
            for root_permission in self.descriptor.config.get(
                    "initial_root_permissions", list()
            ):
                self.context.rpc_manager.call.auth_add_group_permission(
                    1, 1, root_permission
                )
        #
        user_provider_id = auth_ctx["provider_attr"]["nameid"]
        # Ensure user is present
        if auth_ctx["user_id"] is None:
            user_email = auth_ctx["provider_attr"].get("attributes", {}).get("email") or \
                         f"{user_provider_id}@centry.user"
            user_name = user_provider_id
            user_id = self.context.rpc_manager.call.auth_add_user(user_email, user_name)
            #
            self.context.rpc_manager.call.auth_add_user_provider(user_id, user_provider_id)
            self.context.rpc_manager.call.auth_add_user_group(user_id, 1)
            #
            auth_ctx["user_id"] = user_id
            if "/AITrial" in auth_ctx["provider_attr"].get("attributes", {}).get("groups", []):
                self.context.event_manager.fire_event("new_ai_user", {"user_id": user_id, "user_email": user_email})
            log.info("Created user: %s", user_id)
        #
        user_id = auth_ctx["user_id"]
        # Ensure global_admin is set

        _, returning_name = self.context.rpc_manager.call.auth_update_user(
            id_=user_id, last_login=datetime.now())
        if not returning_name:
            self.context.rpc_manager.call.auth_update_user(id_=user_id, name=user_provider_id)

        global_admin_role = "admin"

        initial_global_admins = self.descriptor.config.get("initial_global_admins", list())

        if user_provider_id in initial_global_admins:
            global_user_roles = self.context.rpc_manager.call.auth_get_user_roles(
                user_id
            )
            log.info("User roles: %s", global_user_roles)
            if global_admin_role not in global_user_roles:

                self.context.rpc_manager.call.auth_assign_user_to_role(
                    user_id,
                    global_admin_role
                )
                log.info("Added role for %s: %s", user_id, global_admin_role)

                # Auth: add project token
                all_tokens = self.context.rpc_manager.call.auth_list_tokens(user_id)
                #
                if len(all_tokens) < 1:
                    token_id = self.context.rpc_manager.call.auth_add_token(
                        user_id, "api",
                        # expires=datetime.datetime.now()+datetime.timedelta(seconds=30),
                    )
                else:
                    token_id = all_tokens[0]["id"]
                #
                #
                token = self.context.rpc_manager.call.auth_encode_token(token_id)
                self.context.rpc_manager.call.secrets_add_token(token)
        return auth_ctx
