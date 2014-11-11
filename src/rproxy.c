/*
 * rproxy.c
 * Functions for a reverse (socks) proxy (used for FDR support).
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
#include <stdlib.h>
#include <inttypes.h>
#include <libimobiledevice/libimobiledevice.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <event2/event.h>

#include "rproxy.h"
#include "socks5.h"
#include "common.h"
#include "thread.h"

#define REVERSE_PROXY_MUX_PORT (1082)

#define RPROXY_CONTROL_PROTOCOL_VERSION ((uint64_t)2)
#define RPROXY_CONNECTION_PROTOCOL_VERSION ((uint64_t)2)

#define RPROXY_RECV_TIMEOUT (10000)

#define CONTROL_CONNECTION_START_STRING ("BeginCtrl")
#define CLIENT_CONNECTION_START_STRING ("HelloConn")

#define CONTROL_RECV_TIMEOUT (3600) /* 1 hour */

#define CONTROL_MSG_CONNECT (0x1)

#define RPROXY_CONTROL_CONNTECTION_ATTEMPTS (5)

struct rproxy_client_private
{
	thread_t thread;
	struct event_base * ev_base;
};

/* FIXME: join with rproxy_client_t? */
typedef struct
{
	idevice_t device;
	idevice_connection_t control_connection;
	uint16_t connection_port;
	struct event_base * ev_base;
} control_thread_context_t;

/* TODO: Move idevice_connection_send_all\idevice_connection_receive_all to libimobiledevice? */
static idevice_error_t idevice_connection_send_all(idevice_connection_t connection, const char * data, uint32_t length)
{
	size_t cur_bytes_sent = 0;
	size_t total_bytes_sent = 0;
	size_t bytes_left = length;
	idevice_error_t res = IDEVICE_E_SUCCESS;

	while (total_bytes_sent < length) {
		res = idevice_connection_send(connection, data + total_bytes_sent, bytes_left, &cur_bytes_sent);
		if (IDEVICE_E_SUCCESS != res) {
			error("ERROR: Unable to send data\n");
			break;
		}

		total_bytes_sent += cur_bytes_sent;
		bytes_left -= cur_bytes_sent;
	}

	return res;
}

static uint64_t get_time_ms()
{
#ifdef WIN32
	return (uint64_t)GetTickCount();
#else
	/* TODO: use clock_gettime (CLOCK_MONOTONIC) when possible */
	struct timeval tv;
	if (0 != gettimeofday(&tv, NULL)) {
		return 0;
	}

	return ((tv.tv_sec * (uint64_t)1000) + (uint64_t)tv.tv_usec);
#endif
}

static idevice_error_t idevice_connection_receive_all(idevice_connection_t connection, char * data, uint32_t length, unsigned int timeout)
{
	size_t cur_bytes_received = 0;
	size_t total_bytes_received = 0;
	size_t bytes_left = length;
	idevice_error_t res = IDEVICE_E_SUCCESS;

	uint64_t start_time = get_time_ms();
	uint64_t time_passed = 0;
	while ((total_bytes_received < length) && (time_passed <= timeout)) {
		res = idevice_connection_receive_timeout(connection, 
												 data + total_bytes_received, 
												 bytes_left, 
												 &cur_bytes_received, 
												 timeout - (unsigned int)time_passed);
		if (IDEVICE_E_SUCCESS != res) {
			error("ERROR: Unable to receive data\n");
			break;
		}

		total_bytes_received += cur_bytes_received;
		bytes_left -= cur_bytes_received;

		time_passed = get_time_ms() - start_time;
	}
	
	/* Check if we've failed to receive the requested amount of data */
	if ((IDEVICE_E_SUCCESS == res) && (total_bytes_received < length)) {
		/* Timeout */
		return IDEVICE_E_NOT_ENOUGH_DATA;
	}

	return res;
}

static int rproxy_send_dict(idevice_connection_t connection, plist_t dict)
{
	int res = -1;
	char * content = NULL;
	uint32_t length = 0;

	/* Convert dict to a binary plist buffer */
	plist_to_bin(dict, &content, &length);
	if ((NULL == content) || (0 == length)) {
		goto cleanup;
	}

	/* Send the size of the plist buffer */
	if (IDEVICE_E_SUCCESS != idevice_connection_send_all(connection, (const char *)&length, sizeof(length))) {
		goto cleanup;
	}

	/* Send the actual buffer */
	if (IDEVICE_E_SUCCESS != idevice_connection_send_all(connection, content, length)) {
		goto cleanup;
	} 

	res = 0;

cleanup:
	if (content) {
		plist_free_memory(content);
	}
	return res; 
}

static int rproxy_recv_dict(idevice_connection_t connection, plist_t * dict, unsigned int timeout)
{
	int res = -1;
	char * content = NULL;
	uint32_t dict_length = 0;

	/* Read the size of the plist buffer */
	if (IDEVICE_E_SUCCESS != idevice_connection_receive_all(connection, (char *)&dict_length, sizeof(dict_length), timeout)) {
		error("ERROR: Failed to receive plist size\n");
		goto cleanup;
	} 

	/* Allocate a buffer for the plist */
	content = (char*)malloc(dict_length);
	if (NULL == content) {
		error("ERROR: Out of memory\n");
		goto cleanup;
	}

	/* Read the plist */
	if (IDEVICE_E_SUCCESS != idevice_connection_receive_all(connection, content, dict_length, timeout)) {
		error("ERROR: Failed to receive plist data\n");
		goto cleanup;
	} 

	/* Finally, parse the plist */
	plist_from_bin(content, dict_length, dict);
	if (*dict) {
		res = 0;
	}
	else {
		error("ERROR: Failed to parse the recieved plist\n");
	}

cleanup:
	if (content) {
		free(content);
	}
	return res;
}

static int get_plist_uint_val(plist_t dict, const char * key, uint64_t * val)
{
	plist_t node = plist_dict_get_item(dict, key);
	if (NULL == node) {
		return -1;
	}
	if (PLIST_UINT != plist_get_node_type(node)) {
		return -1;
	}

	plist_get_uint_val(node, val);
	return 0;
}

static int rproxy_create_connection(idevice_t device, uint16_t port, const char * start_msg, idevice_connection_t * connection)
{
	idevice_connection_t new_connection = NULL;

	/* Connect to the proxt port on the device */
	if (IDEVICE_E_SUCCESS != idevice_connect(device, port, &new_connection)) {
		goto cleanup;
	}

	/* Send the start string, including the null terminator */
	uint32_t msg_size = strlen(start_msg) + 1;
	if (IDEVICE_E_SUCCESS != idevice_connection_send_all(new_connection, start_msg, msg_size)) {
		goto cleanup;
	}

	*connection = new_connection;
	return 0;

cleanup:
	if (new_connection) {
		idevice_disconnect(new_connection);
	}
	return -1;
}

static int handle_connect_msg(control_thread_context_t * context)
{
	idevice_connection_t client_connection = NULL;
	if (IDEVICE_E_SUCCESS != rproxy_create_connection(context->device, 
													  context->connection_port, 
													  CLIENT_CONNECTION_START_STRING, 
													  &client_connection)) {
		error("ERROR: Failed to connect to connection port\n");
		goto cleanup;
	}

	plist_t dict = NULL;
	if (0 != rproxy_recv_dict(client_connection, &dict, RPROXY_RECV_TIMEOUT)) {
		error("ERROR: Failed receive connection protocol's dict\n");
		goto cleanup;
	}

	/* Parse the connection protocol version from the response */
	uint64_t conn_protocol_ver = 0;
	if (get_plist_uint_val(dict, "ConnProtoVersion", &conn_protocol_ver) < 0) {
		error("ERROR: Invalid connection protocol plist\n");
		goto cleanup;
	}
	if (RPROXY_CONNECTION_PROTOCOL_VERSION != conn_protocol_ver) {
		error("WARNING: connection protocol mismatch (received "PRIu64", expected "PRIu64")", 
			  conn_protocol_ver, 
			  RPROXY_CONNECTION_PROTOCOL_VERSION);
	}

	/* FIXME: Check\Store the identifier? */
	
	/* Create a new socks client for the connection (and start handling the new connection) */
	if (0 != socks5_add_client_socket(context->ev_base, client_connection)) {
		error("ERROR: Failed to initialize socks client\n");
		goto cleanup;
	}

	return 0;

cleanup:
	if (client_connection) {
		idevice_disconnect(client_connection);
	}
	return -1;
}

static void libevent_logcb(int severity, const char * msg)
{
	const char * level = "?";
    switch (severity) {
        case _EVENT_LOG_DEBUG: level = "debug"; break;
		case _EVENT_LOG_MSG:   level = "msg";   break;
		case _EVENT_LOG_WARN:  level = "warn";  break;
		case _EVENT_LOG_ERR:   level = "error"; break;
		default:               level = "?";     break; /* never reached */
    }

	debug("libevent [%s] - %s\n", level, msg);
}

static void libevent_fatalcb(int err)
{
	error("ERROR: libevent fatal error %d", err);

	/* According to libevent's docs, this callback shouldn't return to libevent */
	/* FIXME: Fail gracefully */
	exit(EXIT_FAILURE);
}

static void rproxy_control_read_cb(struct bufferevent * bev, void * arg)
{
	control_thread_context_t * context = (control_thread_context_t *)arg;
	uint32_t command = 0;
	struct evbuffer * buffer = bufferevent_get_input(bev);
	size_t data_size = evbuffer_get_length(buffer);

	/* Make sure we have enough data */
	if (data_size < sizeof(command)) {
		return;
	}

	evbuffer_copyout(buffer, &command, sizeof(command));

	if (CONTROL_MSG_CONNECT == command) {
		handle_connect_msg(context);
	}
	else {
		error("WARNING: Unknown control command: %u", command);
	}
}

static void rproxy_control_event_cb(struct bufferevent *bev, short what, void *arg)
{
	if (what & BEV_EVENT_TIMEOUT) {
		error("ERROR: A timeout has occurred on the proxy's control connection\n");
	}
	if (what & BEV_EVENT_EOF) {	
		debug("proxy's control connection was closed");
	}
	if (what & BEV_EVENT_ERROR) {
		error("ERROR: An error has occured on the proxy's control connection\n");
	}
}

static int create_control_socket_event(struct event_base * base, control_thread_context_t * context, struct bufferevent ** control_event)
{
	struct bufferevent * new_event = NULL;
	int sock_fd = -1;
	struct timeval read_timeout = { 0 };
	
	/* Get the connection's socket */
	if (IDEVICE_E_SUCCESS != idevice_connection_get_fd(context->control_connection, &sock_fd)) {
		error("ERROR: Failed to get the socket for the reverse proxy's control connection\n");
		goto cleanup;
	}

	/* libevent needs sockets to be non-blocking */
	if (0 != evutil_make_socket_nonblocking(sock_fd)) {
		error("ERROR: Failed to make the reverse proxy's control socket non-blocking\n");
		goto cleanup;
	}

	/* Create a new bufferevent for the control socket */
	new_event = bufferevent_socket_new(base, sock_fd, 0);
	if (NULL == new_event) {
		error("ERROR: Failed to initialize the reverse proxy's control socket\n");
		goto cleanup;
	}

	/* Init the new bufferevent */
	bufferevent_setcb(new_event, rproxy_control_read_cb, NULL, rproxy_control_event_cb, (void*)context);
	read_timeout.tv_sec = CONTROL_RECV_TIMEOUT;
	read_timeout.tv_usec = 0;
	bufferevent_set_timeouts(new_event, &read_timeout, NULL);

	/* Each control message is a 32bit unsigned int, so tell libevent to call
	 * our read callback only were there is enough data */
	bufferevent_setwatermark(new_event, EV_READ, sizeof(uint32_t), 0);

	/* Enable both read & write events */
	if (0 != bufferevent_enable(new_event, EV_READ | EV_WRITE)) {
		error("ERROR: Failed to enable the proxy's control socket\n");
		goto cleanup;
	}

	*control_event = new_event;
	return 0;

cleanup:
	if (new_event) {
		bufferevent_free(new_event);
	}

	return -1;
}

static void * rproxy_thread_proc(void * parameter)
{
   	control_thread_context_t * context = (control_thread_context_t *)parameter;
	struct bufferevent * control_event = NULL;

	/* Create a bufferevent for the control socket */
	if (0 != create_control_socket_event(context->ev_base, context, &control_event)) {
		error("ERROR: Failed to configure the reverse proxy control socket\n");
		goto cleanup;
	}
	
	/* Run the event loop */
	if (0 != event_base_dispatch(context->ev_base)) {
		error("ERROR: Failed to start the reverse proxy's event loop\n");
	}
		
	/* Cleanup */
cleanup:
	if (control_event) {
		bufferevent_free(control_event);
	}
	idevice_disconnect(context->control_connection);
	free(context);

	return NULL;
}

static int rproxy_connect_control_service(idevice_t device, idevice_connection_t * control_connection, uint16_t * connection_port)
{
	plist_t dict = NULL;

	/* Connect to the proxy service */
	idevice_connection_t new_connection = NULL;
	if (IDEVICE_E_SUCCESS != rproxy_create_connection(device, REVERSE_PROXY_MUX_PORT, CONTROL_CONNECTION_START_STRING, &new_connection)) {
		error("ERROR: Failed to connect to the proxy service\n");
		goto cleanup;
	}

	/* Send the BeginCtrl command */
	dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("BeginCtrl"));
	plist_dict_set_item(dict, "CtrlProtoVersion", plist_new_uint(RPROXY_CONTROL_PROTOCOL_VERSION));
	
	if (0 != rproxy_send_dict(new_connection, dict)) {
		error("ERROR: Failed send BeginCtrl command to the service\n");
		goto cleanup;
	}
	plist_free(dict);
	dict = NULL;

	/* Get the BeginCtrl's response */
	if (0 != rproxy_recv_dict(new_connection, &dict, RPROXY_RECV_TIMEOUT)) {
		error("ERROR: Failed receive a response for BeginCtrl\n");
		goto cleanup;
	}

	/* Parse the recieved protocol version */
	uint64_t device_ctrl_proto_ver = 0;
	if (get_plist_uint_val(dict, "CtrlProtoVersion", &device_ctrl_proto_ver) < 0) {
		error("ERROR: Device response to BeginCtrl doesn't contain a protocol version\n");
		goto cleanup;
	}
	if (RPROXY_CONTROL_PROTOCOL_VERSION != device_ctrl_proto_ver) {
		error("ERROR: Proxy protocol version mismatch: expected "PRIu64", device reported "PRIu64"\n",
			  RPROXY_CONTROL_PROTOCOL_VERSION, 
			  device_ctrl_proto_ver);
		goto cleanup;
	}

	/* Parse the connection port from the response */
	uint64_t received_conn_port = 0;
	if (get_plist_uint_val(dict, "ConnPort", &received_conn_port) < 0) {
		error("ERROR: Device response to BeginCtrl is missing a connection port\n");
		goto cleanup;
	}
	debug("Reverse proxy connection port: %us", (uint16_t)received_conn_port);
	
	plist_free(dict);
	dict = NULL;

	*control_connection = new_connection;
	*connection_port = (uint16_t)received_conn_port;
	return 0;

cleanup:
	if (dict) {
		plist_free(dict);
	}
	if (new_connection) {
		idevice_disconnect(new_connection);
	}
	
	return -1;
}

int rproxy_start(idevice_t device, rproxy_client_t * client)
{
	struct rproxy_client_private * new_client = NULL;
	idevice_connection_t control_connection = NULL;
	control_thread_context_t * thread_ctx = NULL;
	struct event_base * ev_base = NULL;

#ifdef WIN32
	/* Initialize Winsock */
	WSADATA wsaData = { 0 };
	if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		error("ERROR: Failed to initialize Winsock\n");
		return -1;
	}
#endif

	/* Initialize libevent */
	event_set_fatal_callback(libevent_fatalcb);
	event_set_log_callback(libevent_logcb);
#ifdef WIN32
	if (0 != evthread_use_windows_threads()){
		error("ERROR: Failed to initialize libevent's threading support\n");
		goto cleanup;
	}
#else
	if (0 != evthread_use_pthreads()) {
		error("ERROR: Failed to initialize libevent's threading support\n");
		goto cleanup;
	}
#endif
#ifdef _DEBUG
	event_enable_debug_mode();
#endif

	/* Create a new client struct  */
	new_client = (rproxy_client_private *)calloc(1, sizeof(rproxy_client_private));
	if (NULL == new_client) {
		error("ERROR: Out of memory\n");
		goto cleanup;
	}

	/* Create an event base */
	new_client->ev_base = event_base_new();
	if (NULL == new_client->ev_base) {
		error("ERROR: Failed to initialize libevent\n");
		goto cleanup;
	}

	/* Connect to the proxy service */
	uint16_t conn_port = 0;
	int i = 0;
	for (i = 1; i <= RPROXY_CONTROL_CONNTECTION_ATTEMPTS; i++) {
		if (0 == rproxy_connect_control_service(device, &control_connection, &conn_port)) {
			break;
		}

		if (RPROXY_CONTROL_CONNTECTION_ATTEMPTS == i) {
			error("ERROR: Failed to initialize reverse proxy connection\n");
			goto cleanup;
		}

		sleep(1);
		debug("Failed to connect to the proxy, retrying...\n");
	}

	/* Start a new thread for the reverse proxy event loop */
	thread_ctx = (control_thread_context_t *)calloc(1, sizeof(control_thread_context_t));
	if (NULL == thread_ctx) {
		error("ERROR: Out of memory\n");
		goto cleanup;
	}
	thread_ctx->device = device;
	thread_ctx->control_connection = control_connection;
	thread_ctx->connection_port = (uint16_t)conn_port;
	thread_ctx->ev_base = new_client->ev_base;
	
	if (0 != thread_create(&(new_client->thread), rproxy_thread_proc, thread_ctx)) {
		error("ERROR: Failed to start the reverse proxy thread\n");
		goto cleanup;
	}

	info("Reverse proxy is running\n");
	*client = new_client;
	return 0;

cleanup:
	if (control_connection) {
		idevice_disconnect(control_connection);
	}
	if (new_client) {
		if (new_client->ev_base) {
			event_base_free(new_client->ev_base);
		}
		free(new_client);
	}
	if (thread_ctx) {
		free(thread_ctx);
	}
#ifdef WIN32
	WSACleanup();
#endif

	return -1;
}

int rproxy_stop(rproxy_client_t client)
{
	/* Stop the proxy thread's event loop */
	if (0 != event_base_loopbreak(client->ev_base)) {
		error("ERROR: Failed to stop the reverse proxy thread\n");
		return -1;
	}

	/* Wait for the proxy thread to finish */
	thread_join(client->thread);

	event_base_free(client->ev_base);
	free(client);

	return 0;
}