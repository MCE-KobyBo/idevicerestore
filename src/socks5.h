/*******************************************************************************
 * socks5.h
 * SOCKS Proxy for iOS devices, based on oddsock (https://code.google.com/p/oddsock):
 * 
 * oddsock
 * A flexible SOCKS proxy server.
 *
 * Copyright 2011 Stephen Larew. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY STEPHEN LAREW ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL STEPHEN LAREW OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of Stephen Larew.
 *
 ******************************************************************************/

#ifndef ODDSOCK_SOCKS5_H
#define ODDSOCK_SOCKS5_H

#include <event2/bufferevent.h>

enum socks5_conn_status {
	SCONN_INIT = 0,
	SCONN_CLIENT_MUST_CLOSE,
	SCONN_WAIT_AUTH,
	SCONN_AUTHORIZED,
	SCONN_CONNECT_WAIT,
	SCONN_CONNECT_TRANSMITTING
};

#define SOCKS5_CLIENT_TIMEOUT (300) /* In seconds (5 Min)*/

#ifdef _MSC_VER
	#define __attribute__(A)
	#pragma pack(push, 1)
#endif

#define SOCKS5_AUTH_NONE			(0x00)
#define SOCKS5_AUTH_USER_PASS		(0x02)
#define SOCKS5_AUTH_UNACCEPTABLE	(0xFF)

/* SOCKS auth request,a ccording to rfc 1929:
 * +----+------+----------+------+----------+
 * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 * +----+------+----------+------+----------+
 * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 * +----+------+----------+------+----------+
 */
#define SOCKS5_AUTH_REQUEST_MAX_SIZE (1 + 1 + 255 + 1 + 255)
#define SOCKS5_AUTH_VERSION (1)
#define SOCKS5_AUTH_VERSION_OFFSET (0)
#define SOCKS5_AUTH_USERNAME_LEN_OFFSET (1)
#define SOCKS5_AUTH_USERNAME_OFFSET (2)
#define SOCKS5_AUTH_STATUS_SUCCESS (0)

typedef struct __attribute__((__packed__))
{
	unsigned char version;
	unsigned char status;
} socks5_auth_response;

#define SOCKS5_CMD_CONNECT		(0x01)
#define SOCKS5_CMD_BIND			(0x02)
#define SOCKS5_CMD_UDP_ASSOC	(0x03)
#define SOCKS5_CMD_VALID(cmd) \
	(((cmd) > 0x00) && ((cmd) < 0x04))

#define SOCKS5_ATYPE_IPV4	(0x01)
#define SOCKS5_ATYPE_DOMAIN	(0x03)
#define SOCKS5_ATYPE_IPV6	(0x04)
#define SOCKS5_ATYPE_VALID(cmd) \
	(((cmd) > 0x00) && ((cmd) < 0x05) && ((cmd) != 0x02))

#define SOCKS5_REP_SUCCEEDED			(0x00)
#define SOCKS5_REP_GENERAL_FAILURE		(0x01)
#define SOCKS5_REP_NOT_ALLOWED			(0x02)
#define SOCKS5_REP_NET_UNREACHABLE		(0x03)
#define SOCKS5_REP_HOST_UNREACHABLE		(0x04)
#define SOCKS5_REP_CONN_REFUSED			(0x05)
#define SOCKS5_REP_TTL_EXPIRED			(0x06)
#define SOCKS5_REP_BAD_COMMAND			(0x07)
#define SOCKS5_REP_ATYPE_UNSUPPORTED	(0x08)

typedef struct __attribute__((__packed__))
{
	uint16_t command;
	uint32_t dict_length;
} socks5_command_request_header;

#ifdef _MSC_VER
	#pragma pack(pop)
#endif

/*
 * socks5_conn
 */
struct socks5_conn {
	struct bufferevent *client;
	idevice_connection_t client_connection;
	struct bufferevent *dst;
	enum socks5_conn_status status;
	unsigned char auth_method;
	unsigned char command;
};

int socks5_add_client_socket(struct event_base * base, idevice_connection_t client_connection);

#endif

