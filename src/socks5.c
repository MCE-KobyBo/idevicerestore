/*******************************************************************************
 * socks5.c
 * SOCKS Proxy for iOS devices, based on oddsock (https://code.google.com/p/oddsock),
 * modified by Koby Boyango:
 * - Intergrated with idevicerestore (use mux connections, removed listening socket,
 *   (replaced logging functions, etc.)
 * - Added username\password authentication support (rfc 1929).
 * - Windows (and Visual Studio) support.
 * - Minor cleanups.
 * 
 * oddsock:
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

#include <stdbool.h>
#include <sys/types.h>
#ifdef _MSC_VER
	#include <stdint.h>
	#include <WinSock2.h>
	#include <ws2tcpip.h>
#else
	#include <sys/socket.h>
	#include <netdb.h>
	#include <arpa/inet.h>
#endif

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <libimobiledevice/libimobiledevice.h>

#include "socks5.h"
#include "common.h"

static const unsigned char SOCKS5_SUPPORTED_AUTH_METHODS[] = { SOCKS5_AUTH_USER_PASS, SOCKS5_AUTH_NONE };

struct evdns_base *g_dns_base = NULL;

static int socks5_conn_id(struct socks5_conn *sconn);
static void socks5_conn_free(struct socks5_conn *sconn);

static int socks5_process_greeting(struct socks5_conn *sconn);
static int socks5_process_command_request(struct socks5_conn * sconn);
static void socks5_choose_auth_method(struct socks5_conn *sconn, unsigned char *methods, unsigned char nmethods);
static int socks5_process_request(struct socks5_conn *sconn);
static int socks5_process_auth(struct socks5_conn *sconn);
static int socks5_connect_reply(struct socks5_conn *sconn);
static void socks5_client_readcb(struct bufferevent *bev, void *arg);
static void socks5_client_eventcb(struct bufferevent *bev, short what, void *arg);
static void socks5_dst_readcb(struct bufferevent *bev, void *arg);
static void socks5_dst_eventcb(struct bufferevent *bev, short what, void *arg);
static void socks5_client_close_on_finished_writecb(struct bufferevent * bev, void * arg);

#ifdef _MSC_VER
/* Taken from http://memset.wordpress.com/2010/10/09/inet_ntop-for-win32/ */
static const char* inet_ntop(int af, const void* src, char* dst, int cnt)
{
	struct sockaddr_in srcaddr;

	memset(&srcaddr, 0, sizeof(struct sockaddr_in));
	memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));

	srcaddr.sin_family = af;
	if (WSAAddressToString((struct sockaddr*) &srcaddr, sizeof(struct sockaddr_in), 0, dst, (LPDWORD)&cnt) != 0) {
		debug("WSAAddressToString(): %d\n", WSAGetLastError());
		return NULL;
	}
	return dst;
}
#endif

/*
 * socks5_add_client_socket
 */
int socks5_add_client_socket(struct event_base * base, idevice_connection_t client_connection)
{
	struct timeval tv;
	struct socks5_conn * sconn = NULL;

	/* Get the new connection's fd */
	int client_fd = -1;
	if (IDEVICE_E_SUCCESS != idevice_connection_get_fd(client_connection, &client_fd)) {
		debug("ERROR: failed to get the socket for a connection\n");
		return -1;
	}

	/* libevent needs sockets to be non-blocking */
	if (evutil_make_socket_nonblocking(client_fd) < 0) {
		debug("ERROR: (%d) failed setting accepted socket to nonblocking\n", client_fd);
		return -1;
	}

	/* Allocate a new client connection */
	sconn = (struct socks5_conn*)malloc(sizeof(struct socks5_conn));
	if (!sconn) {
		debug("ERROR: (%d) failed allocating socks5_conn\n", client_fd);
		return -1;
	}
	memset(sconn, 0, sizeof(struct socks5_conn));

	sconn->status = SCONN_INIT;

	sconn->client = bufferevent_socket_new(base, client_fd, 0);
	if (!sconn->client) {
		debug("ERROR: (%d) failed creating client bufferevent\n", client_fd);
		socks5_conn_free(sconn);
		return -1;
	}

	bufferevent_setcb(sconn->client, socks5_client_readcb, NULL, socks5_client_eventcb, (void*)sconn);

	/* Set a read timeout so that clients that connect but don't send
	 * anything are disconnected. */
	tv.tv_sec = SOCKS5_CLIENT_TIMEOUT;
	tv.tv_usec = 0;
	bufferevent_set_timeouts(sconn->client, &tv, NULL);

	if (bufferevent_enable(sconn->client, EV_READ|EV_WRITE) != 0) {
		debug("ERROR: (%d) failed to enable read/write on client\n", client_fd);
		socks5_conn_free(sconn);
		return -1;
	}

	/* Only set the client connection when we know everything when OK (so above calls to socks5_conn_free won't
	* close the connection, and let the caller do it) */
	sconn->client_connection = client_connection;

	return 0;
}

/*
 * socks5_conn_id
 */
static int socks5_conn_id(struct socks5_conn *sconn)
{
	if (!sconn || !sconn->client)
		return -1;

	return bufferevent_getfd(sconn->client);
}

/*
 * socks5_conn_free
 */
static void socks5_conn_free(struct socks5_conn *sconn)
{
	if (sconn) {
		debug("(%d) freeing connection\n", socks5_conn_id(sconn));
		if (sconn->client) {
			bufferevent_free(sconn->client);
		}
		if (sconn->dst) {
			bufferevent_free(sconn->dst);
		}
		if (sconn->client_connection) {
			idevice_disconnect(sconn->client_connection);
		}
		
		memset(sconn, 0, sizeof(struct socks5_conn));
		free(sconn);
	}
}

/*
 * socks5_process_greeting
 * returns:
 *	-1 = error
 *	0  = incomplete
 *	1  = complete
 */
static int socks5_process_greeting(struct socks5_conn *sconn)
{
	struct evbuffer *buffer;
	size_t have;
	unsigned char greeting[2];
	unsigned char nmethods;
	unsigned char *methods = NULL;
	unsigned char greeting_reply[2];

	if (!sconn ||
		sconn->status != SCONN_INIT ||
		!sconn->client)
		return -1;
	
	buffer = bufferevent_get_input(sconn->client);
	have = evbuffer_get_length(buffer);

	if (have < 1)
		return 0;

	evbuffer_copyout(buffer, (void*)greeting, 1);

	if (0xaa == greeting[0]) {
		if (have < 2) {
			return 0;
		}

		evbuffer_copyout(buffer, (void*)greeting, 2);
		if (0xbb == greeting[1]) {
			return socks5_process_command_request(sconn);
		}
	}

	/* Check version field. */
	if (greeting[0] != 0x05)
		return -1;

	if (have < 2)
		return 0;

	/* Get number of methods. */
	evbuffer_copyout(buffer, (void*)greeting, 2);
	nmethods = greeting[1];

	if (have < (2 + nmethods))
		return 0;
	else if (have > (2 + nmethods))
		return -1;

	/* Finally, get the list of supported methods. */
	methods = (unsigned char*)malloc(nmethods);
	if (!methods)
		return -1;

	evbuffer_drain(buffer, sizeof(greeting));
	evbuffer_remove(buffer, (void*)methods, nmethods); /* XXXerr */

	/* Choose which auth method to use. */
	socks5_choose_auth_method(sconn, methods, nmethods);
	free(methods);

	/* Respond with chosen method. */
	greeting_reply[0] = 0x05;
	greeting_reply[1] = sconn->auth_method;
	if (bufferevent_write(sconn->client,
				greeting_reply, sizeof(greeting_reply)) != 0)
		return -1;
	
	/* XXX If chosen auth method is "unacceptable" then perhaps a timer
	 * should be set that when expired closes the connection. */

	/* Set new connection state. */
	if (sconn->auth_method != SOCKS5_AUTH_UNACCEPTABLE) {
		debug("(%d) auth method: %d\n", socks5_conn_id(sconn), (int)sconn->auth_method);
		if (SOCKS5_AUTH_NONE == sconn->auth_method) {
			sconn->status = SCONN_AUTHORIZED;
		}
		else {
			debug("(%d) Waiting for auth...\n", socks5_conn_id(sconn));
			sconn->status = SCONN_WAIT_AUTH;
		}
	} else {
		/* rfc1928 says that the client MUST close the conneciton. */
		sconn->status = SCONN_CLIENT_MUST_CLOSE;
	}

	return 1;
}

/*
 * socks5_choose_auth_method
 */
static void socks5_choose_auth_method(struct socks5_conn *sconn,
		unsigned char *methods, unsigned char nmethods)
{
	sconn->auth_method = SOCKS5_AUTH_UNACCEPTABLE;

	for (size_t i = 0; i < sizeof(SOCKS5_SUPPORTED_AUTH_METHODS); i++) {
		for (size_t j = 0; j < nmethods; ++j) {
			if (SOCKS5_SUPPORTED_AUTH_METHODS[i] == methods[j]) {
				sconn->auth_method = SOCKS5_SUPPORTED_AUTH_METHODS[i];
				return;
			}
		}
	}
}

/*
 * socks5_process_auth
 */
static int socks5_process_auth(struct socks5_conn *sconn)
{
	struct evbuffer * buffer = NULL;
	size_t have = 0;
	size_t size_needed = 0;
	socks5_auth_response auth_response = { 0 };
	char auth_req[SOCKS5_AUTH_REQUEST_MAX_SIZE];
	memset(&auth_req, 0, sizeof(auth_req));
	unsigned char username_len = 0;
	unsigned char password_len = 0;

	if ((!sconn) || (sconn->status != SCONN_WAIT_AUTH) || (!sconn->client)) {
		return -1;
	}

	buffer = bufferevent_get_input(sconn->client);
	have = evbuffer_get_length(buffer);
	
	/* ver, ulen, plen */
	size_needed = 3;
	if (have < size_needed) {
		return 0;
	}
	evbuffer_copyout(buffer, auth_req, size_needed);
	
	/* Verify the request's version */
	if (SOCKS5_AUTH_VERSION != auth_req[SOCKS5_AUTH_VERSION_OFFSET]) {
		return -1;
	}

	/* Make sure we have enough data for the user name name - and read it (and 
	 * the password length) */
	username_len = auth_req[SOCKS5_AUTH_USERNAME_LEN_OFFSET];
	size_needed += username_len;
	if (have < size_needed) {
		return 0;
	}
	evbuffer_copyout(buffer, auth_req, size_needed);

	/* Make sure we have enough data for the password */
	password_len = auth_req[SOCKS5_AUTH_USERNAME_OFFSET + username_len];
	size_needed += password_len;
	if (have < size_needed) {
		return 0;
	}
	
	/* Finally, read the entire request */
	evbuffer_remove(buffer, auth_req, size_needed);

	/* Note: username\password are NOT null terminated */
	char * username = auth_req + SOCKS5_AUTH_USERNAME_OFFSET;
	if (password_len > 0) {
		char * password = auth_req + size_needed - password_len;
		debug("(%d) auth request for: %.*s %.*s\n", socks5_conn_id(sconn), (int)username_len, username, (int)password_len, password);
	}
	else {
		debug("(%d) auth request for: %.*s (empty passowrd)\n", socks5_conn_id(sconn), (int)username_len, username);
	}
	
	/* Currently will allow any username\password */
	auth_response.version = SOCKS5_AUTH_VERSION;
	auth_response.status = SOCKS5_AUTH_STATUS_SUCCESS;
	bufferevent_write(sconn->client, &auth_response, sizeof(auth_response));

	sconn->status = SCONN_AUTHORIZED;
	return 0;
}

/*
 * socks5_client_send_plist
 */
static int socks5_client_send_plist(struct socks5_conn * sconn, plist_t dict)
{
	int res = -1;
	char * content = NULL;
	uint32_t length = 0;
	uint32_t bytes_sent = 0;

	/* Convert the dict to a binary plist buffer */
	plist_to_bin(dict, &content, &length);
	if ((NULL == content) || (0 == length)) {
		goto cleanup;
	}

	/* Send a 4-byte dict size, followed by the dict buffer */
	if (0 != bufferevent_write(sconn->client, &length, sizeof(length))) {
		goto cleanup;
	} 
	if (0 != bufferevent_write(sconn->client, content, length)) {
		goto cleanup;
	}

	res = 0;

cleanup:
	if (content) {
		plist_free_memory(content);
	}
	return res; 
}

/*
 * socks5_process_command_request
 */
static int socks5_process_command_request(struct socks5_conn * sconn)
{
	int res = -1;
	struct evbuffer * buffer = bufferevent_get_input(sconn->client);
	size_t have = evbuffer_get_length(buffer);
	socks5_command_request_header request_header = { 0 };
	char * request_content = NULL;
	size_t total_request_size = 0;
	plist_t request_dict = NULL;
	plist_t response_dict = NULL;

	/* Make sure we have enough data for the request header, and read it */
	if (sizeof(request_header) > have) {
		res = 0;
		goto cleanup;
	}
	evbuffer_copyout(buffer, (void*)&request_header, sizeof(request_header));
	
	/* Make sure we have enough data for the entire request */
	total_request_size = sizeof(request_header) + request_header.dict_length;
	if (have < total_request_size) {
		res = 0;
		goto cleanup;
	}

	/* Allocate a buffer for the entire request */
	request_content = (char*)malloc(total_request_size);
	if (NULL == request_content) {
		goto cleanup;
	}

	/* Read & parse the plist */
	evbuffer_remove(buffer, request_content, total_request_size);
	plist_from_bin(request_content + sizeof(request_header), request_header.dict_length, &request_dict);
	if (NULL == request_dict) {
		goto cleanup;
	}

	/* Get the command */
	char * command = NULL;
	plist_t command_node = plist_dict_get_item(request_dict, "Command");
	if ((NULL == command_node) || (PLIST_STRING != plist_get_node_type(command_node))) {
		debug("ERROR: (%d) Missing command node\n", socks5_conn_id(sconn));
		goto cleanup;
	}
	
	plist_get_string_val(command_node, &command);
	if (NULL == plist_get_string_val) {
		debug("ERROR: (%d) Failed get command node value\n", socks5_conn_id(sconn));
		goto cleanup;
	}

	/* Currently the only known command is "Ping" */
	if (0 == strcmp(command, "Ping")) {
		response_dict = plist_new_dict();
		plist_dict_set_item(response_dict, "Pong", plist_new_bool(1));
		if (0 != socks5_client_send_plist(sconn, response_dict)) {
			debug("ERROR: (%d) Failed send command response\n", socks5_conn_id(sconn));
			goto cleanup;
		}
	} 
	else {
		debug("WARNING: (%d) Unknown command: %s\n", socks5_conn_id(sconn), command);
		goto cleanup;
	}

	/* Close the connection after the response is written */
	bufferevent_setcb(sconn->client, NULL, socks5_client_close_on_finished_writecb, socks5_client_eventcb, NULL);
	bufferevent_disable(sconn->client, EV_READ);

	res = 0;

cleanup:
	if (request_content) {
		free(request_content);
	}
	if (request_dict) {
		plist_free(request_dict);
	}
	if (response_dict) {
		plist_free(response_dict);
	}

	return res;
}

/*
 * socks5_process_request
 */
static int socks5_process_request(struct socks5_conn *sconn)
{
	struct evbuffer *buffer;
	size_t have;
	unsigned char request[6+256]; /* fixed + variable address */
	unsigned char request_reply[2] = { 0x05, 0x00 };
	unsigned char atype;
	int af;
	char addr[256]; /* max(unsigned char) + NULL terminator */
	unsigned short port;

	if (!sconn ||
		sconn->status != SCONN_AUTHORIZED ||
		!sconn->client)
		return -1;
	
	buffer = bufferevent_get_input(sconn->client);
	have = evbuffer_get_length(buffer);

	if (have < 1)
		return 0;
	evbuffer_copyout(buffer, (void*)request, 1);

	/* Check version field. */
	if (request[0] != 0x05)
		return -1;

	if (have < 8)
		return 0;
	evbuffer_copyout(buffer, (void*)request, 8);

	/* Get command and address type. */
	if (!SOCKS5_CMD_VALID(request[1])) {
		request_reply[1] = SOCKS5_REP_BAD_COMMAND;
		bufferevent_write(sconn->client, request_reply, 2);
		return -1;
	}
	sconn->command = request[1];

	if (!SOCKS5_ATYPE_VALID(request[3])) {
		request_reply[1] = SOCKS5_REP_BAD_COMMAND;
		bufferevent_write(sconn->client, request_reply, 2);
		return -1;
	}
	atype = request[3];

	/* Get the address and port. */
	if (atype == SOCKS5_ATYPE_IPV4) {
		if (have < 10)
			return 0;
		else if (have > 10)
			return -1;

		evbuffer_remove(buffer, (void*)request, 10);

		af = AF_INET;
		if (!inet_ntop(af, &request[4], addr, sizeof(addr))) {
			debug("ERROR: (%d) inet_ntop failed while processing request\n", socks5_conn_id(sconn));
			request_reply[1] = SOCKS5_REP_GENERAL_FAILURE;
			bufferevent_write(sconn->client, request_reply, 2);
			return -1;
		}

		port = ntohs(*((unsigned short*)&request[8]));
	}
	else if (atype == SOCKS5_ATYPE_IPV6) {
		if (have < 22)
			return 0;
		else if (have > 22)
			return -1;

		evbuffer_remove(buffer, (void*)request, 22);

		af = AF_INET6;
		if (!inet_ntop(af, &request[4], addr, sizeof(addr))) {
			debug("ERROR: (%d) inet_ntop failed while processing request\n", socks5_conn_id(sconn));
			request_reply[1] = SOCKS5_REP_GENERAL_FAILURE;
			bufferevent_write(sconn->client, request_reply, 2);
			return -1;
		}

		port = ntohs(*((unsigned short*)&request[20]));
	}
	else if (atype == SOCKS5_ATYPE_DOMAIN) {
		unsigned char addrlen;

		addrlen = request[4];
		if (have < (7 + addrlen))
			return 0;
		else if (have > (7 + addrlen))
			return -1;

		evbuffer_remove(buffer, (void*)request, (7 + addrlen));

		af = AF_UNSPEC;
		memcpy(addr, &request[5], addrlen);
		addr[addrlen] = '\0';
		port = ntohs(*((unsigned short*)&request[5+addrlen]));
	}

	/* Handle request. */
	if (sconn->command == SOCKS5_CMD_CONNECT) {
		/* CONNECT request. */
		debug("(%d) socks connection request for %s port %u\n", socks5_conn_id(sconn), addr, port);

		/* Create dst bufferevent. */
		sconn->dst = bufferevent_socket_new(bufferevent_get_base(sconn->client), -1,
											BEV_OPT_CLOSE_ON_FREE);
		if (!sconn->dst) {
			debug("ERROR: (%d) failed creating dst bufferevent\n", socks5_conn_id(sconn));
			request_reply[1] = SOCKS5_REP_GENERAL_FAILURE;
			bufferevent_write(sconn->client, request_reply, 2);
			return -1;
		}

		bufferevent_setcb(sconn->dst, socks5_dst_readcb, NULL, socks5_dst_eventcb, (void*)sconn);

		/* Make sure the DNS resolver is ready. */
		if (!g_dns_base) {
			g_dns_base = evdns_base_new(bufferevent_get_base(sconn->client), 1);
			if (!g_dns_base) {
				debug("ERROR: (%d) failed creating evdns_base\n", socks5_conn_id(sconn));
			}
		}

		/* Connect to destination. */
		if (bufferevent_socket_connect_hostname(sconn->dst, g_dns_base, af, addr, port) != 0) {
			debug("ERROR: (%d) failed creating dst bufferevent\n", socks5_conn_id(sconn));
			request_reply[1] = SOCKS5_REP_GENERAL_FAILURE;
			bufferevent_write(sconn->client, request_reply, 2);
			return -1;
		}

		sconn->status = SCONN_CONNECT_WAIT;
	}
	else {
		/* Only CONNECT is implemented right now. */
		debug("ERROR: (%d) unsupported command %u requested\n", socks5_conn_id(sconn), sconn->command);
		request_reply[1] = SOCKS5_REP_BAD_COMMAND;
		bufferevent_write(sconn->client, request_reply, 2);
		return -1;
	}

	return 1;
}

/*
 * socks5_connect_reply
 */
static int socks5_connect_reply(struct socks5_conn *sconn)
{
	unsigned char reply[5];
	struct sockaddr_storage ssaddr;
	socklen_t sslen = sizeof(ssaddr);
	int dstfd;

	reply[0] = 0x05;
	dstfd = bufferevent_getfd(sconn->dst);

	memset(&ssaddr, 0, sizeof(ssaddr));
	if (getsockname(dstfd, (struct sockaddr*)&ssaddr, &sslen) < 0) {
		/* Notify client of failure and close. */
		reply[1] = SOCKS5_REP_GENERAL_FAILURE;
		bufferevent_write(sconn->client, reply, 2);
		return -1;
	}

	reply[1] = SOCKS5_REP_SUCCEEDED;
	reply[2] = 0x00;

	if (ssaddr.ss_family == AF_INET) {
		struct sockaddr_in *saddr = (struct sockaddr_in*)&ssaddr;
		reply[3] = SOCKS5_ATYPE_IPV4;
		bufferevent_write(sconn->client, reply, 4); 
		bufferevent_write(sconn->client, &saddr->sin_addr, sizeof(saddr->sin_addr));
		bufferevent_write(sconn->client, &saddr->sin_port, 2);
	}
	else if (ssaddr.ss_family == AF_INET6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6*)&ssaddr;
		reply[3] = SOCKS5_ATYPE_IPV6;
		bufferevent_write(sconn->client, reply, 4); 
		bufferevent_write(sconn->client, &saddr->sin6_addr, sizeof(saddr->sin6_addr));
		bufferevent_write(sconn->client, &saddr->sin6_port, 2);
	}
	else {
		/* Notify client of failure and close. */
		reply[1] = SOCKS5_REP_GENERAL_FAILURE;
		bufferevent_write(sconn->client, reply, 2);
		return -1;
	}

	sconn->status = SCONN_CONNECT_TRANSMITTING;

	if (bufferevent_enable(sconn->dst, EV_READ|EV_WRITE) != 0) {
		debug("ERROR: (%d) failed to enable read/write on dst\n", socks5_conn_id(sconn));
		return -1;
	}

	return 0;
}

/*
 * socks5_client_readcb
 */
static void socks5_client_readcb(struct bufferevent *bev, void *arg)
{
	struct socks5_conn *sconn = (struct socks5_conn*)arg;
	int e;

	if (!sconn || !bev) {
		debug("ERROR: socks5_client_readcb invalid args\n");
		return;
	}

	if (sconn->status == SCONN_INIT) {
		bufferevent_set_timeouts(sconn->client, NULL, NULL);

		e = socks5_process_greeting(sconn);
		if (e < 0) {
			debug("ERROR: (%d) error processing client greeting\n", socks5_conn_id(sconn));
			socks5_conn_free(sconn);
		}
	}
	else if (sconn->status == SCONN_CLIENT_MUST_CLOSE) {
		/* The client MUST close the connection yet it is still sending
		 * something so close the connection. */
		debug("WARNING: (%d) client not rfc1928 conformant\n", socks5_conn_id(sconn));
		socks5_conn_free(sconn);
	}
	else if (sconn->status == SCONN_WAIT_AUTH) {
		e = socks5_process_auth(sconn);
		if (e < 0) {
			debug("ERROR: (%d) error processing client auth\n", socks5_conn_id(sconn));
			socks5_conn_free(sconn);
		}
	}
	else if (sconn->status == SCONN_AUTHORIZED) {
		e = socks5_process_request(sconn);
		if (e < 0) {
			debug("ERROR: (%d) error processing client request\n", socks5_conn_id(sconn));
			socks5_conn_free(sconn);
		}
	}
	else if (sconn->status == SCONN_CONNECT_WAIT) {
		/* Client sent data while waiting on request reply.
		 * Treat this as an errant client and clost connection. */
		debug("WARNING: (%d) errant client\n", socks5_conn_id(sconn));
		socks5_conn_free(sconn);
	}
	else if (sconn->status == SCONN_CONNECT_TRANSMITTING) {
		bufferevent_read_buffer(sconn->client, bufferevent_get_output(sconn->dst));
	}
}

/*
 * socks5_client_eventcb
 */
static void socks5_client_eventcb(struct bufferevent *bev, short what, void *arg)
{
	struct socks5_conn *sconn = (struct socks5_conn*)arg;

	if (!sconn || !bev) {
		debug("ERROR: socks5_client_eventcb invalid args\n");
		return;
	}

	if (what & BEV_EVENT_TIMEOUT) {
		debug("(%d) client timeout\n", socks5_conn_id(sconn));
		socks5_conn_free(sconn);
		return;
	}
	if (what & BEV_EVENT_EOF) {
		/* Client closed the connection. */
		debug("(%d) client closed connection\n", socks5_conn_id(sconn));
		socks5_conn_free(sconn);
		return;
	}
	if (what & BEV_EVENT_ERROR) {
		debug("ERROR: (%d) client connection error\n", socks5_conn_id(sconn));
		socks5_conn_free(sconn);
		return;
	}
}

/*
 * socks5_dst_readcb
 */
static void socks5_dst_readcb(struct bufferevent *bev, void *arg)
{
	struct socks5_conn *sconn = (struct socks5_conn*)arg;

	if (!sconn || !sconn->client || !sconn->dst) {
		return;
	}
		
	if (sconn->status == SCONN_CONNECT_TRANSMITTING) {
		bufferevent_read_buffer(sconn->dst, bufferevent_get_output(sconn->client));
	}
}

/*
 * socks5_dst_eventcb
 */
static void socks5_dst_eventcb(struct bufferevent *bev, short what, void *arg)
{
	struct socks5_conn *sconn = (struct socks5_conn*)arg;

	if (!sconn || !bev) {
		debug("ERROR: socks5_dst_eventcb invalid args\n");
		return;
	}

	if (what & BEV_EVENT_CONNECTED) {
		if (socks5_connect_reply(sconn) < 0) {
			debug("ERROR: (%d) failed sending request reply\n", socks5_conn_id(sconn));
			socks5_conn_free(sconn);
			return;
		}
		debug("(%d) CONNECT succeeded\n", socks5_conn_id(sconn));
		return;
	}
	if (what & BEV_EVENT_EOF) {
		/* Destination closed the connection. */
		debug("(%d) destination closed connection\n", socks5_conn_id(sconn));
		socks5_conn_free(sconn);
		return;
	}
	if (what & BEV_EVENT_ERROR) {
		int e = bufferevent_socket_get_dns_error(bev);
		if (e != 0) {
			debug("ERROR: (%d) DNS error: %s\n", socks5_conn_id(sconn), gai_strerror(e));
		}
		else {
			debug("ERROR: (%d) destination connection error\n", socks5_conn_id(sconn));
		}
			
		socks5_conn_free(sconn);
		return;
	}
}

/*
 * socks5_client_close_on_finished_writecb
 */
static void socks5_client_close_on_finished_writecb(struct bufferevent * bev, void * arg)
{
	struct socks5_conn * sconn = (struct socks5_conn*)arg;
	struct evbuffer * buffer = bufferevent_get_output(bev);
	
	/* Close the client connection after the output buffer was flushed */
	if (evbuffer_get_length(buffer) == 0) {
		socks5_conn_free(sconn);
	}
}