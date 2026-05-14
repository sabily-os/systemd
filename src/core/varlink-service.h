/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int service_context_build_json(sd_json_variant **ret, const char *name, void *userdata);
