/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "json-util.h"
#include "service.h"
#include "varlink-common.h"
#include "varlink-service.h"

/* TODO: This covers only a small subset of a service object's properties. Extend to make more available to
 * consumers like Unit.StartTransient */
int service_context_build_json(sd_json_variant **ret, const char *name, void *userdata) {
        Unit *u = ASSERT_PTR(userdata);
        Service *s = ASSERT_PTR(SERVICE(u));
        assert(ret);

        return sd_json_buildo(
                        ret,
                        JSON_BUILD_PAIR_ENUM("Type", service_type_to_string(s->type)),
                        JSON_BUILD_PAIR_CALLBACK_NON_NULL("ExecStart", exec_command_list_build_json, s->exec_command[SERVICE_EXEC_START]),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RemainAfterExit", s->remain_after_exit));
}
