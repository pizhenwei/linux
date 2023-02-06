/* SPDX-License-Identifier: BSD-3-Clause */
/* This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers. */
#ifndef _LINUX_VIRTIO_OF_H
#define _LINUX_VIRTIO_OF_H

#include <linux/virtio_types.h>

enum virtio_of_connection_type {
	virtio_of_connection_tcp,
	virtio_of_connection_rdma
};

enum virtio_of_opcode {
	/* Connect */
	virtio_of_op_connect = 0,
	/* Disconnect */
	virtio_of_op_discconnect,
	/* Keepalive */
	virtio_of_op_keepalive,
	/* Get features of virtio-over-fabrics */
	virtio_of_op_get_feature,
	/* Set features of virtio-over-fabrics */
	virtio_of_op_set_feature,
	/* TODO discovery */
	/* TODO auth */

	/* Get vendor ID - 32b */
	virtio_of_op_get_vendor_id = 4096,
	/* Get device ID - 32b */
	virtio_of_op_get_device_id,
	/* Get configuration generation - 32b */
	virtio_of_op_get_generation,
	/* Get status - 32b */
	virtio_of_op_get_status,
	/* Set status */
	virtio_of_op_set_status,
	/* Get bitmask of the feature supported by the device - 64b */
	virtio_of_op_get_device_feature,
	/* Set bitmask of the feature supported by the host */
	virtio_of_op_set_driver_feature,
	/* Get the number of queues - 16b */
	virtio_of_op_get_num_queues,
	/* Get size of a queue - 16b */
	virtio_of_op_get_queue_size,
	/* Set size of a queue */
	virtio_of_op_set_queue_size,
	/* Get the config of per-device - 8b/16b/32b/64b */
	virtio_of_op_get_config,
	/* Set the config of per-device */
	virtio_of_op_set_config,
	/* Get the config of per-device until changed - 8b */
	virtio_of_op_get_config_changed,

	/* Payload of virtio ring */
	virtio_of_op_vring = 8192,
};

enum virtio_of_feature {
	/* max segs in a single vring request. for opcode virtio_of_op_get_feature */
	virtio_of_feature_max_segs,
};

union virtio_of_value {
	__u8 u8;
	__le16 u16;
	__le32 u32;
	__le64 u64;
};

struct virtio_of_connect {
	__u8 ivqn[256];
	__u8 tvqn[256];
	__u8 rsvd[512];
};

struct virtio_of_command_connect {
	__le16 opcode;
	__le16 command_id;
	__le16 target_id;
	__le16 queue_id;
	__le16 ndesc;
	__u8 oftype; /* enum virtio_of_connection_type */
	__u8 rsvd[5];
};

struct virtio_of_command_common {
	__le16 opcode;
	__le16 command_id;
	__u8 rsvd4;
	__u8 rsvd5;
	__u8 rsvd6;
	__u8 rsvd7;
	union virtio_of_value value;	/* ignore this field on GET */
};

struct virtio_of_command_feature {
	__le16 opcode;
	__le16 command_id;
	__le32 feature_select;
	__le64 value;	/* ignore this field on GET */
};

struct virtio_of_command_queue {
	__le16 opcode;
	__le16 command_id;
	__le16 queue_id;
	__u8 rsvd6;
	__u8 rsvd7;
	__le64 value;   /* ignore this field on GET */
};

struct virtio_of_command_config {
	__le16 opcode;
	__le16 command_id;
	__le16 offset;
	__u8 bytes;
	__u8 rsvd7;
	union virtio_of_value value;	/* ignore this field on GET */
};

struct virtio_of_command_status {
	__le16 opcode;
	__le16 command_id;
	__le32 status;	/* ignore this field on GET */
	__u8 rsvd[8];
};

struct virtio_of_vring_desc {
	__le64 addr;
	__le32 length;
	__le16 id;
	__le16 flags;
	union {
		__le32 key;
	};
};

struct virtio_of_command_vring {
	__le16 opcode;
	__le16 command_id;
	__le32 length;
	__le16 ndesc;
	__u8 rsvd[6];
};

struct virtio_of_command {
	union {
		struct virtio_of_command_common common;
		struct virtio_of_command_connect connect;
		struct virtio_of_command_feature feature;
		struct virtio_of_command_queue queue;
		struct virtio_of_command_config config;
		struct virtio_of_command_status status;
		struct virtio_of_command_vring vring;
	};
};

struct virtio_of_completion {
	__le16 status;
	__le16 command_id;
	__le16 ndesc;
	__u8 rsvd6;
	__u8 rsvd7;
	union virtio_of_value value;
};

enum virtio_of_status {
	VIRTIO_OF_SUCCESS = 0,
	VIRTIO_OF_EPERM = 1,
	VIRTIO_OF_ENOENT = 2,
	VIRTIO_OF_ESRCH = 3,
	VIRTIO_OF_EINTR = 4,
	VIRTIO_OF_EIO = 5,
	VIRTIO_OF_ENXIO = 6,
	VIRTIO_OF_E2BIG = 7,
	VIRTIO_OF_ENOEXEC = 8,
	VIRTIO_OF_EBADF = 9,
	VIRTIO_OF_ECHILD = 10,
	VIRTIO_OF_EAGAIN = 11,
	VIRTIO_OF_ENOMEM = 12,
	VIRTIO_OF_EACCES = 13,
	VIRTIO_OF_EFAULT = 14,
	VIRTIO_OF_ENOTBLK = 15,
	VIRTIO_OF_EBUSY = 16,
	VIRTIO_OF_EEXIST = 17,
	VIRTIO_OF_EXDEV = 18,
	VIRTIO_OF_ENODEV = 19,
	VIRTIO_OF_ENOTDIR = 20,
	VIRTIO_OF_EISDIR = 21,
	VIRTIO_OF_EINVAL = 22,
	VIRTIO_OF_ENFILE = 23,
	VIRTIO_OF_EMFILE = 24,
	VIRTIO_OF_ENOTTY = 25,
	VIRTIO_OF_ETXTBSY = 26,
	VIRTIO_OF_EFBIG = 27,
	VIRTIO_OF_ENOSPC = 28,
	VIRTIO_OF_ESPIPE = 29,
	VIRTIO_OF_EROFS = 30,
	VIRTIO_OF_EMLINK = 31,
	VIRTIO_OF_EPIPE = 32,
	VIRTIO_OF_EDOM = 33,
	VIRTIO_OF_ERANGE = 34,
	VIRTIO_OF_EDEADLK = 35,
	VIRTIO_OF_ENAMETOOLONG = 36,
	VIRTIO_OF_ENOLCK = 37,
	VIRTIO_OF_ENOSYS = 38,
	VIRTIO_OF_ENOTEMPTY = 39,
	VIRTIO_OF_ELOOP = 40,
	VIRTIO_OF_EWOULDBLOCK = 41,
	VIRTIO_OF_ENOMSG = 42,
	VIRTIO_OF_EIDRM = 43,
	VIRTIO_OF_ECHRNG = 44,
	VIRTIO_OF_EL2NSYNC = 45,
	VIRTIO_OF_EL3HLT = 46,
	VIRTIO_OF_EL3RST = 47,
	VIRTIO_OF_ELNRNG = 48,
	VIRTIO_OF_EUNATCH = 49,
	VIRTIO_OF_ENOCSI = 50,
	VIRTIO_OF_EL2HLT = 51,
	VIRTIO_OF_EBADE = 52,
	VIRTIO_OF_EBADR = 53,
	VIRTIO_OF_EXFULL = 54,
	VIRTIO_OF_ENOANO = 55,
	VIRTIO_OF_EBADRQC = 56,
	VIRTIO_OF_EBADSLT = 57,
	VIRTIO_OF_EDEADLOCK = 58,
	VIRTIO_OF_EBFONT = 59,
	VIRTIO_OF_ENOSTR = 60,
	VIRTIO_OF_ENODATA = 61,
	VIRTIO_OF_ETIME = 62,
	VIRTIO_OF_ENOSR = 63,
	VIRTIO_OF_ENONET = 64,
	VIRTIO_OF_ENOPKG = 65,
	VIRTIO_OF_EREMOTE = 66,
	VIRTIO_OF_ENOLINK = 67,
	VIRTIO_OF_EADV = 68,
	VIRTIO_OF_ESRMNT = 69,
	VIRTIO_OF_ECOMM = 70,
	VIRTIO_OF_EPROTO = 71,
	VIRTIO_OF_EMULTIHOP = 72,
	VIRTIO_OF_EDOTDOT = 73,
	VIRTIO_OF_EBADMSG = 74,
	VIRTIO_OF_EOVERFLOW = 75,
	VIRTIO_OF_ENOTUNIQ = 76,
	VIRTIO_OF_EBADFD = 77,
	VIRTIO_OF_EREMCHG = 78,
	VIRTIO_OF_ELIBACC = 79,
	VIRTIO_OF_ELIBBAD = 80,
	VIRTIO_OF_ELIBSCN = 81,
	VIRTIO_OF_ELIBMAX = 82,
	VIRTIO_OF_ELIBEXEC = 83,
	VIRTIO_OF_EILSEQ = 84,
	VIRTIO_OF_ERESTART = 85,
	VIRTIO_OF_ESTRPIPE = 86,
	VIRTIO_OF_EUSERS = 87,
	VIRTIO_OF_ENOTSOCK = 88,
	VIRTIO_OF_EDESTADDRREQ = 89,
	VIRTIO_OF_EMSGSIZE = 90,
	VIRTIO_OF_EPROTOTYPE = 91,
	VIRTIO_OF_ENOPROTOOPT = 92,
	VIRTIO_OF_EPROTONOSUPPORT = 93,
	VIRTIO_OF_ESOCKTNOSUPPORT = 94,
	VIRTIO_OF_EOPNOTSUPP = 95,
	VIRTIO_OF_EPFNOSUPPORT = 96,
	VIRTIO_OF_EAFNOSUPPORT = 97,
	VIRTIO_OF_EADDRINUSE = 98,
	VIRTIO_OF_EADDRNOTAVAIL = 99,
	VIRTIO_OF_ENETDOWN = 100,
	VIRTIO_OF_ENETUNREACH = 101,
	VIRTIO_OF_ENETRESET = 102,
	VIRTIO_OF_ECONNABORTED = 103,
	VIRTIO_OF_ECONNRESET = 104,
	VIRTIO_OF_ENOBUFS = 105,
	VIRTIO_OF_EISCONN = 106,
	VIRTIO_OF_ENOTCONN = 107,
	VIRTIO_OF_ESHUTDOWN = 108,
	VIRTIO_OF_ETOOMANYREFS = 109,
	VIRTIO_OF_ETIMEDOUT = 110,
	VIRTIO_OF_ECONNREFUSED = 111,
	VIRTIO_OF_EHOSTDOWN = 112,
	VIRTIO_OF_EHOSTUNREACH = 113,
	VIRTIO_OF_EALREADY = 114,
	VIRTIO_OF_EINPROGRESS = 115,
	VIRTIO_OF_ESTALE = 116,
	VIRTIO_OF_EUCLEAN = 117,
	VIRTIO_OF_ENOTNAM = 118,
	VIRTIO_OF_ENAVAIL = 119,
	VIRTIO_OF_EISNAM = 120,
	VIRTIO_OF_EREMOTEIO = 121,
	VIRTIO_OF_EDQUOT = 122,
	VIRTIO_OF_ENOMEDIUM = 123,
	VIRTIO_OF_EMEDIUMTYPE = 124,
	VIRTIO_OF_ECANCELED = 125,
	VIRTIO_OF_ENOKEY = 126,
	VIRTIO_OF_EKEYEXPIRED = 127,
	VIRTIO_OF_EKEYREVOKED = 128,
	VIRTIO_OF_EKEYREJECTED = 129,
	VIRTIO_OF_EOWNERDEAD = 130,
	VIRTIO_OF_ENOTRECOVERABLE = 131,
	VIRTIO_OF_ERFKILL = 132,
	VIRTIO_OF_EHWPOISON = 133,
	VIRTIO_OF_EQUIRK = 4096
};

#endif
