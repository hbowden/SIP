

/**
 * Copyright (c) 2015, Harrison Bowden, Minneapolis, MN
 * 
 * Permission to use, copy, modify, and/or distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright notice 
 * and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH 
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY 
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, 
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/module.h>
#include <security/mac/mac_policy.h>

static struct mtx sip_mtx;

/* An array of paths to protect from modification. */
static const char *protected_paths[] = { "/sbin", "/bin", "/usr", "/lib", "/usr/include", "/usr/sbin" };

static int get_pathname_file(struct *vp, char **name, char **freebuf)
{


	return (0);
}

static int get_pathname_dir(struct *dvp, char **name)
{
	return (0);
}

static void 
init_sip(struct mac_policy_conf *mpc)
{
    mtx_init(&sip_mtx, "System integrity protection lock", NULL, MTX_DEF);

	return;
}

static void 
destroy_sip(struct mac_policy_conf *mpc)
{
    mtx_destroy(&sip_mtx);

	return;
}

static int 
sip_check_access(struct ucred *cred, struct vnode *vp,
	             struct label *vplabel, accmode_t accmode)
{
    return (0);
}

static int 
sip_check_chroot(struct ucred *cred, struct vnode *dvp, 
	             struct label *dvplabel)
{
	return (0);
}

static int
sip_check_create(struct ucred *cred, struct vnode *dvp, struct label *dvplabel,
		         struct componentname *cnp, struct vattr *vap)
{
	return (0);
}

static int
sip_check_deleteacl(struct ucred *cred, struct vnode *vp, 
	                struct label *vplabel, acl_type_t type)
{
	return (0);
}

static int
sip_check_deleteextattr(struct ucred *cred, struct vnode *vp, 
	                    struct label *vplabel, int attrnamespace, 
	                    const char *name)
{
	return (0);
}

static int 
sip_check_link(struct ucred *cred, struct vnode *dvp,
	           struct label *dvplabel, struct vnode *vp, struct label *label,
	           struct componentname *cnp)
{
    return (0);
}

static int 
sip_check_mmap(struct ucred *cred, struct vnode *vp, 
	           struct label *label, int prot, int flags)
{
	return (0);
}

static int 
sip_check_open(struct ucred *cred, struct vnode *vp,
	           struct label *vplabel, accmode_t accmode)
{
    return (0);
}

static int
sip_check_rename_from(struct ucred *cred, struct vnode *dvp, 
	                  struct label *dvplabel, struct vnode *vp, 
	                  struct label *vplabel, struct componentname *cnp)
{

	return (0);
}

static int
sip_check_rename_to(struct ucred *cred, struct vnode *dvp, 
	                struct label *dvplabel, struct vnode *vp, 
	                struct label *vplabel, int samedir,
		            struct componentname *cnp)
{
	return (0);
}

static int
sip_check_setacl(struct ucred *cred, struct vnode *vp, 
	             struct label *vplabel, acl_type_t type,
		         struct acl *acl)
{
	return (0);
}

static int
sip_check_setextattr(struct ucred *cred, struct vnode *vp, 
	                 struct label *vplabel, int attrnamespace, 
	                 const char *name)
{
	return (0);
}

static int
sip_check_setflags(struct ucred *cred, struct vnode *vp,
	               struct label *vplabel, u_long flags)
{
	return (0);
}

static int
sip_check_setmode(struct ucred *cred, struct vnode *vp, 
	              struct label *vplabel, mode_t mode)
{
	return (0);
}

static int
sip_check_setowner(struct ucred *cred, struct vnode *vp, 
	               struct label *vplabel, uid_t uid, gid_t gid)
{
	return (0);
}

static int
sip_check_setutimes(struct ucred *cred, struct vnode *vp, struct label *vplabel,
		            struct timespec atime, struct timespec mtime)
{
	return (0);
}

static int
sip_check_unlink(struct ucred *cred, struct vnode *dvp, struct label *dvplabel,
		         struct vnode *vp, struct label *vplabel, struct componentname *cnp)
{
	return (0);
}

static int
sip_check_write(struct ucred *active_cred, struct ucred *file_cred, 
	            struct vnode *vp, struct label *vplabel)
{
	return (0);
}

/* The MAC entry points we want to handle. */
static struct mac_policy_ops sip_ops = {

	.mpo_init = init_sip,
	.mpo_destroy = destroy_sip,
	.mpo_vnode_check_access = sip_check_access,
	.mpo_vnode_check_chroot = sip_check_chroot,
	.mpo_vnode_check_create = sip_check_create,
	.mpo_vnode_check_deleteacl = sip_check_deleteacl,
	.mpo_vnode_check_deleteextattr = sip_check_deleteextattr,
	.mpo_vnode_check_link = sip_check_link,
	.mpo_vnode_check_mmap = sip_check_mmap,
	.mpo_vnode_check_open = sip_check_open,
	.mpo_vnode_check_rename_from = sip_check_rename_from,
	.mpo_vnode_check_rename_to = sip_check_rename_to,
	.mpo_vnode_check_setacl = sip_check_setacl,
	.mpo_vnode_check_setextattr = sip_check_setextattr,
	.mpo_vnode_check_setflags = sip_check_setflags,
	.mpo_vnode_check_setmode = sip_check_setmode,
	.mpo_vnode_check_setowner = sip_check_setowner,
	.mpo_vnode_check_setutimes = sip_check_setutimes,
	.mpo_vnode_check_unlink = sip_check_unlink,
	.mpo_vnode_check_write = sip_check_write
};

/* Declare the MAC framework policy. */
MAC_POLICY_SET(&sip_ops, mac_sip, "System integrity protection",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
