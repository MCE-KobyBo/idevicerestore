/*
 * rproxy.c
 * Definitions for a reverse (socks) proxy (used for FDR support).
 *
 * Copyright (c) 2014 Koby Boyango. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef IDEVICERESTORE_RPROXY_H
#define IDEVICERESTORE_RPROXY_H

#include <libimobiledevice/libimobiledevice.h>

typedef struct rproxy_client_private rproxy_client_private;
typedef rproxy_client_private *rproxy_client_t;

int rproxy_start(idevice_t device, rproxy_client_t * client);
int rproxy_stop(rproxy_client_t client);

#endif