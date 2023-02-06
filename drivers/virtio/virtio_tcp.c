// SPDX-License-Identifier: GPL-2.0-only
/*
 * VIRTIO Over TCP initiator
 *
 * Copyright (c) 2023, Bytedance Inc. All rights reserved.
 *	Author: zhenwei pi <pizhenwei@bytedance.com>
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/parser.h>
#include <linux/miscdevice.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uuid.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_of.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <linux/virtio_of.h>

#include "virtio_fabrics.h"

#define VTCP_MODULE_AUTHOR	"zhenwei pi <pizhenwei@bytedance.com>"
#define VTCP_MODULE_DESC	"VIRTIO Over TCP initiator"
#define VTCP_MODULE_LICENSE	"GPL v2"
#define VTCP_MODULE_VERSION	"0.1"

static struct workqueue_struct *vtcp_wq;

enum vtcp_request_stage {
	vtcp_req_send_cmd,
	vtcp_req_send_desc,
	vtcp_req_send_vring,
	vtcp_req_recv_comp,
	vtcp_req_recv_desc,
	vtcp_req_recv_vring,
	vtcp_req_recv_done,
};

struct vtcp_request {
	struct vof_request vofreq;
	struct list_head entry;
	struct completion comp;
	struct virtio_of_vring_desc *vofdescs, *rcv_vofdescs;
	u8 **addr;
	u32 cur_off;
	u16 ndesc;	/* total descriptors */
	u16 rcv_ndesc;	/* descriptors to receive */
	u16 cur_desc;	/* descriptor index we are handling currently */
	u8 stage;
};

struct vtcp_queue {
	struct vof_queue vofq;

	struct socket *sock;
	struct work_struct work;
	void (*sk_state_change)(struct sock *sk);
	void (*sk_data_ready)(struct sock *sk);
	void (*sk_write_space)(struct sock *sk);

	struct mutex send_mutex;	/* to avoid re-entry send work */
	struct list_head send_list;	/* queued requests, to be sent */
	spinlock_t send_lock;		/* to protect send_list */

	struct vtcp_request *sendreq, *recvreq;	/* the requests in process */
	struct virtio_of_completion recvcomp;	/* the response in process */
	u8 recvbytes;	/* to describe the received length of recvcomp */
};

struct vtcp_device {
	struct vof_device vofdev;
	struct sockaddr_storage taddr;
	struct sockaddr_storage iaddr;
};

static inline struct vtcp_request *to_vtcpreq(struct vof_request *vofreq)
{
	return container_of(vofreq, struct vtcp_request, vofreq);
}

static inline struct vtcp_queue *to_vtcpq(struct vof_queue *vofq)
{
	return container_of(vofq, struct vtcp_queue, vofq);
}

static inline struct vtcp_device *to_vtcpdev(struct vof_device *vofdev)
{
	return container_of(vofdev, struct vtcp_device, vofdev);
}

static struct vof_request *vtcp_alloc_req(struct vof_queue *vofq, u16 snd_ndesc, u16 rcv_ndesc)
{
	struct vtcp_request *vtcpreq;
	struct virtio_of_command *vofcmd;
	int length;
	u16 ndesc = snd_ndesc + rcv_ndesc;

	/* To reduce kzalloc: combine the request buffer into a single one.
	 * The memory has a layout:
	 * | vtcpreq          |
	 * | vofcmd           |
	 * | desc * ndesc     |
	 * | desc * rcv_ndesc |
	 * | ptr * ndesc      |
	 */
	length = sizeof(struct vtcp_request);
	length += sizeof(struct virtio_of_command);
	length += sizeof(struct virtio_of_vring_desc) * ndesc;
	length += sizeof(struct virtio_of_vring_desc) * rcv_ndesc;
	length += sizeof(u8 *) * ndesc;
	vtcpreq = kzalloc(length, GFP_KERNEL);
	if (!vtcpreq)
		return NULL;

	vtcpreq->stage = vtcp_req_send_cmd;
	vofcmd = (struct virtio_of_command *)(vtcpreq + 1);
	vtcpreq->vofreq.vofcmd = vofcmd;
	if (ndesc) {
		vtcpreq->ndesc = ndesc;
		vtcpreq->vofdescs = (struct virtio_of_vring_desc *)(vofcmd + 1);

		vtcpreq->rcv_ndesc = rcv_ndesc;
		vtcpreq->rcv_vofdescs = vtcpreq->vofdescs + ndesc;

		vtcpreq->addr = (u8 **)(vtcpreq->rcv_vofdescs + rcv_ndesc);
	}

	return &vtcpreq->vofreq;
}

/* vtcp_free_req is called from two scenarios:
 * 1, a request is sent by workqueue(removed from send_list), freed after interrupt
 * 2, a request is queued in send_list and wait to send, freed when destroying queue
 */
static void vtcp_free_req(struct vof_request *vofreq)
{
	struct vtcp_request *vtcpreq = to_vtcpreq(vofreq);
	struct vtcp_queue *vtcpq = to_vtcpq(vofreq->vofq);

	if (unlikely(!list_empty(&vtcpreq->entry))) {
		spin_lock(&vtcpq->send_lock);
		list_del(&vtcpreq->entry);
		spin_unlock(&vtcpq->send_lock);
	}

	kfree(vtcpreq);
}

static int vtcp_map_req(struct vof_request *vofreq, u16 idx, struct vring_desc *desc, u16 id, u32 *_length)
{
	struct vtcp_request *vtcpreq = to_vtcpreq(vofreq);
	struct vof_device *vofdev = vofreq->vofq->vofdev;
	struct virtio_of_vring_desc *vofdesc = vtcpreq->vofdescs + idx;
	void *addr;
	u32 length;
	u16 flags;

	addr = phys_to_virt(virtio64_to_cpu(&vofdev->vdev, desc->addr));
	vtcpreq->addr[idx] = addr;
	length = virtio32_to_cpu(&vofdev->vdev, desc->len);
	flags = virtio16_to_cpu(&vofdev->vdev, desc->flags);

	vofdesc->addr = *_length;
	vofdesc->length = cpu_to_le32(length);
	vofdesc->id = cpu_to_le16(id);
	vofdesc->flags = cpu_to_le16(flags);

	if (flags & VRING_DESC_F_NEXT)
		*_length += length;

	return 0;
}

static int vtcp_queue_req(struct vof_request *vofreq)
{
	struct vtcp_request *vtcpreq = to_vtcpreq(vofreq);
	struct vtcp_queue *vtcpq = to_vtcpq(vofreq->vofq);

	spin_lock(&vtcpq->send_lock);
	list_add_tail(&vtcpreq->entry, &vtcpq->send_list);
	spin_unlock(&vtcpq->send_lock);

	queue_work(vtcp_wq, &vtcpq->work);

	return 0;
}

static int vtcp_queue_send_one(struct vtcp_request *vtcpreq, u8 *addr, u32 tosend, unsigned int msg_flags)
{
	struct vtcp_queue *vtcpq = to_vtcpq(vtcpreq->vofreq.vofq);
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | msg_flags };
	struct kvec iov = { .iov_base = addr, .iov_len = tosend };
	int ret;

	if (!tosend)
		return 0;

	ret = kernel_sendmsg(vtcpq->sock, &msg, &iov, 1, iov.iov_len);
	if (ret <= 0)
		return ret;

	vtcpreq->cur_off += ret;
	if (ret == tosend)
		vtcpreq->cur_off = 0;

	return ret;
}

/* Get TCP MSG flags for vring buffer */
static inline unsigned int vtcp_msg_flags(struct vtcp_request *vtcpreq)
{
	struct virtio_of_vring_desc *vofdesc;

	if (vtcpreq->cur_desc == vtcpreq->ndesc - 1)
		return MSG_EOR;

	/* Tricky! virtio request usually: OUT[OUT] ... [IN] IN */
	vofdesc = &vtcpreq->vofdescs[vtcpreq->cur_desc + 1];
	if (le16_to_cpu(vofdesc->flags) & VRING_DESC_F_WRITE)
		return MSG_EOR;

	return MSG_MORE;
}

/* Return 0 or positive number on success, negative error code on failure. */
static int vtcp_queue_send(struct vtcp_queue *vtcpq)
{
	struct vtcp_request *vtcpreq;
	struct virtio_of_vring_desc *vofdesc;
	u8 *addr;
	unsigned int msg_flags;
	int tosend;
	int ret = 0;

send_one:
	vtcpreq = vtcpq->sendreq;
	if (!vtcpreq) {
		/* try to grab a request from send list */
		spin_lock(&vtcpq->send_lock);
		vtcpreq = list_first_entry_or_null(&vtcpq->send_list, struct vtcp_request, entry);
		if (!vtcpreq) {
			spin_unlock(&vtcpq->send_lock);
			return 0;
		}
		list_del_init(&vtcpreq->entry);
		spin_unlock(&vtcpq->send_lock);

		vtcpq->sendreq = vtcpreq; /* mark this request as sending */
	}

	switch (vtcpreq->stage) {
	case vtcp_req_send_cmd:
		tosend = sizeof(*vtcpreq->vofreq.vofcmd);
		BUG_ON(vtcpreq->cur_off >= tosend);
		tosend -= vtcpreq->cur_off;
		addr = (u8 *)vtcpreq->vofreq.vofcmd + vtcpreq->cur_off;
		msg_flags = vtcpreq->ndesc ? MSG_MORE : MSG_EOR;
		ret = vtcp_queue_send_one(vtcpreq, addr, tosend, msg_flags);
		if (ret < tosend)
			goto out;

		if (!vtcpreq->ndesc) {
			vtcpreq->stage = vtcp_req_recv_comp;
			vtcpq->sendreq = NULL;
			goto send_one;
		}

		vtcpreq->stage = vtcp_req_send_desc;
		fallthrough;

	case vtcp_req_send_desc:
		tosend = sizeof(struct virtio_of_vring_desc) * vtcpreq->ndesc;
		BUG_ON(vtcpreq->cur_off >= tosend);
		tosend -= vtcpreq->cur_off;
		addr = (u8 *)vtcpreq->vofdescs + vtcpreq->cur_off;
		ret = vtcp_queue_send_one(vtcpreq, addr, tosend, MSG_MORE);
		if (ret < tosend)
			goto out;

		vtcpreq->stage = vtcp_req_send_vring;
		fallthrough;

	case vtcp_req_send_vring:
		while (vtcpreq->cur_desc < vtcpreq->ndesc) {
			vofdesc = &vtcpreq->vofdescs[vtcpreq->cur_desc];
			if (le16_to_cpu(vofdesc->flags) & VRING_DESC_F_WRITE) {
				vtcpreq->cur_desc++;
				continue;
			}

			tosend = le32_to_cpu(vofdesc->length);
			BUG_ON(vtcpreq->cur_off >= tosend);
			tosend -= vtcpreq->cur_off;
			addr = (u8 *)vtcpreq->addr[vtcpreq->cur_desc] + vtcpreq->cur_off;
			msg_flags = vtcp_msg_flags(vtcpreq);
			ret = vtcp_queue_send_one(vtcpreq, addr, tosend, msg_flags);
			if (ret < tosend)
				goto out;

			vtcpreq->cur_desc++;
		}

		vtcpreq->cur_desc = 0;
		vtcpreq->stage = vtcp_req_recv_comp;
		vtcpq->sendreq = NULL;
		goto send_one;

	default:
		BUG();
	}

out:
	if (ret == -EAGAIN)
		ret = 0;

	return ret;
}

static int vtcp_skb_copy(struct sk_buff *skb, struct vtcp_request *vtcpreq, u8 *addr, u32 torecv, u32 remained, int offset)
{
	u32 copied;
	int ret;

	copied = min_t(u32, torecv, remained);
	if (!copied)
		return 0;

	ret = skb_copy_bits(skb, offset, addr, copied);
	if (ret)
		return ret;

	vtcpreq->cur_off += copied;
	if (copied == torecv)
		vtcpreq->cur_off = 0;

	return copied;
}

static int vtcp_skb_recv_one(read_descriptor_t *desc, struct sk_buff *skb, unsigned int offset, size_t len)
{
	struct vtcp_queue *vtcpq = desc->arg.data;
	struct vof_queue *vofq = &vtcpq->vofq;
	struct virtio_of_completion *comp;
	struct vof_request *vofreq;
	struct vtcp_request *vtcpreq;
	struct virtio_of_vring_desc *snd_vofdesc, *rcv_vofdesc;
	u8 *addr;
	int torecv;
	int ret;
	u16 command_id, status, ndesc, id;

	vtcpreq = vtcpq->recvreq;
	if (!vtcpreq) {
		comp = &vtcpq->recvcomp;
		torecv = sizeof(struct virtio_of_completion);
		BUG_ON(vtcpq->recvbytes >= torecv);
		torecv -= vtcpq->recvbytes;
		torecv = min_t(u32, torecv, len);
		addr = (u8 *)comp + vtcpq->recvbytes;
		ret = skb_copy_bits(skb, offset, addr, torecv);
		if (ret)
			return ret;

		vtcpq->recvbytes += torecv;
		if (vtcpq->recvbytes < sizeof(struct virtio_of_completion))
			return torecv;

		/* now we have a full virtio_of_completion */
		vtcpq->recvbytes = 0;
		command_id = le16_to_cpu(comp->command_id);
		status = le16_to_cpu(comp->status);
		vofreq = vof_request_load(&vtcpq->vofq, command_id);
		if (!vofreq) {
			dev_err(&vtcpq->vofq.vofdev->vdev.dev, "bad command_id %u", command_id);
			return -EPROTO;	//TODO handle this, reset
		}

		vtcpreq = to_vtcpreq(vofreq);
		if (le16_to_cpu(vtcpreq->vofreq.vofcmd->common.command_id) != command_id) {
			dev_err(&vtcpq->vofq.vofdev->vdev.dev, "unexpected command_id");
			return -EPROTO;	//TODO handle this, reset
		}

		BUG_ON(vtcpreq->stage != vtcp_req_recv_comp);
		vtcpq->recvreq = vtcpreq;
		memcpy(&vtcpreq->vofreq.vofcomp, comp, sizeof(*comp));
		ndesc = le16_to_cpu(vtcpreq->vofreq.vofcomp.ndesc);
		if (ndesc != vtcpreq->rcv_ndesc) {
			dev_err(&vtcpq->vofq.vofdev->vdev.dev, "unexpected ndesc");
			return -EPROTO;
		}

memset(comp, 0xff, sizeof(*comp));//XXX
		if (!ndesc) {
			vtcpreq->stage = vtcp_req_recv_done;
			ret = torecv;
			goto recv_done;
		}

		vtcpreq->stage = vtcp_req_recv_desc;
		return torecv;
	}

	switch (vtcpreq->stage) {
	case vtcp_req_recv_desc:
		torecv = sizeof(struct virtio_of_vring_desc) * vtcpreq->rcv_ndesc;
		BUG_ON(vtcpreq->cur_off >= torecv);
		torecv -= vtcpreq->cur_off;
		addr = (u8 *)vtcpreq->rcv_vofdescs + vtcpreq->cur_off;
		ret = vtcp_skb_copy(skb, vtcpreq, addr, torecv, len, offset);
		if (ret == torecv)
			vtcpreq->stage = vtcp_req_recv_vring;

		return ret;

	case vtcp_req_recv_vring:
		BUG_ON(vtcpreq->cur_desc >= vtcpreq->rcv_ndesc);
		rcv_vofdesc = &vtcpreq->rcv_vofdescs[vtcpreq->cur_desc];
		id = le16_to_cpu(rcv_vofdesc->id);
		for (ndesc = 0; ndesc < vtcpreq->ndesc; ndesc++) {
			snd_vofdesc = &vtcpreq->vofdescs[ndesc];
			if (le16_to_cpu(snd_vofdesc->id) == id)
				break;
		}

		if (ndesc == vtcpreq->ndesc)
			return -EPROTO;

		torecv = le32_to_cpu(rcv_vofdesc->length);
		if (torecv > le32_to_cpu(snd_vofdesc->length))
			return -EPROTO;
		BUG_ON(vtcpreq->cur_off >= torecv);
		torecv -= vtcpreq->cur_off;
		addr = vtcpreq->addr[ndesc] + vtcpreq->cur_off;
		ret = vtcp_skb_copy(skb, vtcpreq, addr, torecv, len, offset);
		if (ret < torecv)
			return ret;

		if (++vtcpreq->cur_desc < vtcpreq->rcv_ndesc)
			return ret;

		vtcpreq->stage = vtcp_req_recv_done;
		goto recv_done;

	default:
		BUG();
	}

recv_done:
	vofq->interrupt(vofq, &vtcpq->recvreq->vofreq.vofcomp);
	vtcpq->recvreq = NULL;

	return ret;
}

static int vtcp_skb_recv(read_descriptor_t *desc, struct sk_buff *skb, unsigned int offset, size_t len)
{
	size_t bytes = len;
	int ret;

	while (bytes) {
		ret = vtcp_skb_recv_one(desc, skb, offset, bytes);
		if (ret < 0)
			return ret;

		offset += ret;
		bytes -= ret;
	}

	return len;
}

static int vtcp_queue_recv(struct vtcp_queue *vtcpq)
{
	struct socket *sock = vtcpq->sock;
	struct sock *sk = sock->sk;
	read_descriptor_t rd_desc;
	int received;

	rd_desc.arg.data = vtcpq;
	rd_desc.count = 1;
	lock_sock(sk);
	received = sock->ops->read_sock(sk, &rd_desc, vtcp_skb_recv);
	release_sock(sk);

	return received;
}

static void vtcp_queue_work(struct work_struct *work)
{
	struct vtcp_queue *vtcpq = container_of(work, struct vtcp_queue, work);

	if (mutex_trylock(&vtcpq->send_mutex)) {
		vtcp_queue_send(vtcpq);//TODO handle error
		mutex_unlock(&vtcpq->send_mutex);
	}

	vtcp_queue_recv(vtcpq);
}

static void vtcp_sk_state_change(struct sock *sk)
{
	struct vtcp_queue *vtcpq;

	read_lock_bh(&sk->sk_callback_lock);
	vtcpq = sk->sk_user_data;
	if (!vtcpq)
		goto unlock;

	switch (sk->sk_state) {
	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
	case TCP_LAST_ACK:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		vof_dev_warn(vtcpq->vofq.vofdev, "socket state changed\n");
		break;
	default:
		vof_dev_warn(vtcpq->vofq.vofdev, "unexpected socket state\n");
	}

	vtcpq->sk_state_change(sk);
unlock:
	read_unlock_bh(&sk->sk_callback_lock);
}

static void vtcp_sk_data_ready(struct sock *sk)
{
	struct vtcp_queue *vtcpq;

	read_lock_bh(&sk->sk_callback_lock);
	vtcpq = sk->sk_user_data;
	if (vtcpq) {
		//queue_work_on(smp_processor_id(), vtcp_wq, &queue->work);
		queue_work(vtcp_wq, &vtcpq->work);
	}
	read_unlock_bh(&sk->sk_callback_lock);
}

static void vtcp_sk_write_space(struct sock *sk)
{
	struct vtcp_queue *vtcpq;

	read_lock_bh(&sk->sk_callback_lock);
	vtcpq = sk->sk_user_data;
	if (vtcpq) {
		//queue_work_on(smp_processor_id(), vtcp_wq, &vtcpq->work);
		queue_work(vtcp_wq, &vtcpq->work);
	}
	read_unlock_bh(&sk->sk_callback_lock);
}

static void vtcp_sk_overwrite_handler(struct vtcp_queue *vtcpq)
{
	write_lock_bh(&vtcpq->sock->sk->sk_callback_lock);
	vtcpq->sock->sk->sk_user_data = vtcpq;
	vtcpq->sk_state_change = vtcpq->sock->sk->sk_state_change;
	vtcpq->sk_data_ready = vtcpq->sock->sk->sk_data_ready;
	vtcpq->sk_write_space = vtcpq->sock->sk->sk_write_space;
	vtcpq->sock->sk->sk_state_change = vtcp_sk_state_change;
	vtcpq->sock->sk->sk_data_ready = vtcp_sk_data_ready;
	vtcpq->sock->sk->sk_write_space = vtcp_sk_write_space;
	write_unlock_bh(&vtcpq->sock->sk->sk_callback_lock);
}

static void vtcp_sk_restore_handler(struct vtcp_queue *vtcpq)
{
	write_lock_bh(&vtcpq->sock->sk->sk_callback_lock);
	vtcpq->sock->sk->sk_user_data = NULL;
	vtcpq->sock->sk->sk_state_change = vtcpq->sk_state_change;
	vtcpq->sock->sk->sk_data_ready = vtcpq->sk_data_ready;
	vtcpq->sock->sk->sk_write_space = vtcpq->sk_write_space;
	write_unlock_bh(&vtcpq->sock->sk->sk_callback_lock);
}

static void vtcp_destroy_queue(struct vof_queue *vofq)
{
	struct vtcp_queue *vtcpq = to_vtcpq(vofq);
	struct vtcp_request *vtcpreq, *n;

	vtcp_sk_restore_handler(vtcpq);
	kernel_sock_shutdown(vtcpq->sock, SHUT_RDWR);
	sock_release(vtcpq->sock);
	cancel_work_sync(&vtcpq->work);

	spin_lock(&vtcpq->send_lock);
	list_for_each_entry_safe(vtcpreq, n, &vtcpq->send_list, entry) {
		list_del(&vtcpreq->entry);
		vtcp_free_req(&vtcpreq->vofreq);
	}
	spin_unlock(&vtcpq->send_lock);

	kfree(vtcpq);
}

static struct vof_queue *vtcp_create_queue(struct vof_device *vofdev, u32 vring_num)
{
	struct vtcp_device *vtcpdev = to_vtcpdev(vofdev);
	struct vtcp_queue *vtcpq;
	int ret;

	vtcpq = kzalloc(sizeof(*vtcpq), GFP_KERNEL);
	if (!vtcpq)
		return ERR_PTR(-ENOMEM);

	ret = sock_create(vtcpdev->taddr.ss_family, SOCK_STREAM, IPPROTO_TCP, &vtcpq->sock);
	if (ret)
		goto free_queue;

	vtcpq->vofq.vofdev = vofdev;
	vtcpq->vofq.vring_num = vring_num;
	vtcpq->sock->sk->sk_rcvtimeo = VOF_TIMEOUT;
	vtcpq->sock->sk->sk_use_task_frag = false;
	vtcpq->sock->sk->sk_allocation = GFP_ATOMIC;
	sk_set_memalloc(vtcpq->sock->sk);
	tcp_sock_set_syncnt(vtcpq->sock->sk, 1);
	tcp_sock_set_nodelay(vtcpq->sock->sk);
	sock_no_linger(vtcpq->sock->sk);

	ret = kernel_connect(vtcpq->sock, (struct sockaddr *)&vtcpdev->taddr, sizeof(vtcpdev->taddr), 0);
	if (ret)
		goto release_sock;

	vtcp_sk_overwrite_handler(vtcpq);
	INIT_LIST_HEAD(&vtcpq->send_list);
	spin_lock_init(&vtcpq->send_lock);
	INIT_WORK(&vtcpq->work, vtcp_queue_work);
	mutex_init(&vtcpq->send_mutex);

	return &vtcpq->vofq;

release_sock:
	sock_release(vtcpq->sock);

free_queue:
	kfree(vtcpq);

	return ERR_PTR(ret);
}

static struct vof_device *vtcp_create(struct vof_options *opts)
{
	struct vtcp_device *vtcpdev;
	int ret;

	vtcpdev = kzalloc(sizeof(*vtcpdev), GFP_KERNEL);
	if (!vtcpdev)
		return ERR_PTR(-ENOMEM);

	ret = inet_pton_with_scope(&init_net, AF_UNSPEC, opts->taddr, opts->tport, &vtcpdev->taddr);
	if (ret)
		goto free_dev;

	if (opts->iaddr) {
		ret = inet_pton_with_scope(&init_net, AF_UNSPEC, opts->iaddr, opts->iport, &vtcpdev->iaddr);
		if (ret)
			goto free_dev;
	}

	vtcpdev->vofdev.opts = opts;
	return &vtcpdev->vofdev;

free_dev:
	kfree(vtcpdev);
	return ERR_PTR(ret);
}

static void vtcp_destroy(struct vof_device *vofdev)
{
	struct vtcp_device *vtcpdev = to_vtcpdev(vofdev);

	kfree(vtcpdev);
}

static struct vof_transport_ops vtcp_transport_ops = {
	.transport = "tcp",
	.oftype = virtio_of_connection_tcp,
	.module = THIS_MODULE,
	.create = vtcp_create,
	.destroy = vtcp_destroy,
	.create_queue = vtcp_create_queue,
	.destroy_queue = vtcp_destroy_queue,
	.alloc_req = vtcp_alloc_req,
	.free_req = vtcp_free_req,
	.queue_req = vtcp_queue_req,
	.map_req = vtcp_map_req,
};

static int __init vtcp_init(void)
{
	vtcp_wq = alloc_workqueue("vtcp_wq", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!vtcp_wq)
		return -ENOMEM;

	return vof_register_transport(&vtcp_transport_ops);
}

static void __exit vtcp_exit(void)
{
	vof_unregister_transport(&vtcp_transport_ops);

	destroy_workqueue(vtcp_wq);
}

module_init(vtcp_init);
module_exit(vtcp_exit);

MODULE_AUTHOR(VTCP_MODULE_AUTHOR);
MODULE_DESCRIPTION(VTCP_MODULE_DESC);
MODULE_LICENSE(VTCP_MODULE_LICENSE);
MODULE_VERSION(VTCP_MODULE_VERSION);
