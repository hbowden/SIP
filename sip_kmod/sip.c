

/**
 * Copyright (c) 2015, Harrison Bowden, Minneapolis, MN
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/types.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <security/mac/mac_policy.h>

static struct rwlock sip_rw;

struct sip_policy
{
	char *path;

    LIST_ENTRY(sip_policy) entries;	
};

MALLOC_DECLARE(M_SIP);

MALLOC_DEFINE(M_SIP, "sip buffer", "SIP hashtable entry buffer");

static LIST_HEAD(sip_list_head, sip_policy) *table;
static u_long table_mask;

/* An array of default paths to protect from modification. */
//static const char *protected_paths[] = { "/sbin", "/bin", "/usr", "/lib", "/usr/include", "/usr/sbin" };

static int
sip_check_filepath(struct vnode *vp)
{
	int error = 0;
	char *fullpath = NULL;
	char *freepath = NULL;

    /* Get the file or directory path name. */
	error = vn_fullpath_global(curthread, vp, &fullpath, &freepath);
	if(error)
	    return (error);

	if (freepath)
		free(freepath, M_TEMP);

    return (0);
}

static int
sip_check_dirpath(struct vnode *dvp)
{

	return (0);
}

static void 
init_sip(struct mac_policy_conf *mpc)
{
	/* Init the reader writer lock. */
    rw_init(&sip_rw, "System integrity protection lock");

    /* Init the hash table. */
    table = hashinit(1024, M_SIP, &table_mask);

	return;
}

static void 
destroy_sip(struct mac_policy_conf *mpc)
{
    rw_destroy(&sip_rw);

    hashdestroy(table, M_SIP, table_mask);

	return;
}

static int 
sip_check_access(struct ucred *cred, struct vnode *vp,
	             struct label *vplabel, accmode_t accmode)
{
    return (sip_check_filepath(vp));
}

static int 
sip_check_chroot(struct ucred *cred, struct vnode *dvp, 
	             struct label *dvplabel)
{
	return (sip_check_dirpath(dvp));
}

static int
sip_check_create(struct ucred *cred, struct vnode *dvp, struct label *dvplabel,
		         struct componentname *cnp, struct vattr *vap)
{
	return (sip_check_dirpath(dvp));
}

static int
sip_check_deleteacl(struct ucred *cred, struct vnode *vp, 
	                struct label *vplabel, acl_type_t type)
{
	return (sip_check_filepath(vp));
}

static int
sip_check_deleteextattr(struct ucred *cred, struct vnode *vp, 
	                    struct label *vplabel, int attrnamespace, 
	                    const char *name)
{
	return (sip_check_filepath(vp));
}

static int 
sip_check_link(struct ucred *cred, struct vnode *dvp,
	           struct label *dvplabel, struct vnode *vp, struct label *label,
	           struct componentname *cnp)
{
    return (sip_check_dirpath(dvp));
}

static int 
sip_check_mmap(struct ucred *cred, struct vnode *vp, 
	           struct label *label, int prot, int flags)
{
	return (sip_check_filepath(vp));
}

static int 
sip_check_open(struct ucred *cred, struct vnode *vp,
	           struct label *vplabel, accmode_t accmode)
{
    return (sip_check_filepath(vp));
}

static int
sip_check_rename_from(struct ucred *cred, struct vnode *dvp, 
	                  struct label *dvplabel, struct vnode *vp, 
	                  struct label *vplabel, struct componentname *cnp)
{

	return (sip_check_dirpath(vp));
}

static int
sip_check_rename_to(struct ucred *cred, struct vnode *dvp, 
	                struct label *dvplabel, struct vnode *vp, 
	                struct label *vplabel, int samedir,
		            struct componentname *cnp)
{
	return (sip_check_dirpath(dvp));
}

static int
sip_check_setacl(struct ucred *cred, struct vnode *vp, 
	             struct label *vplabel, acl_type_t type,
		         struct acl *acl)
{
	return (sip_check_filepath(vp));
}

static int
sip_check_setextattr(struct ucred *cred, struct vnode *vp, 
	                 struct label *vplabel, int attrnamespace, 
	                 const char *name)
{
	return (sip_check_filepath(vp));
}

static int
sip_check_setflags(struct ucred *cred, struct vnode *vp,
	               struct label *vplabel, u_long flags)
{
	return (sip_check_filepath(vp));
}

static int
sip_check_setmode(struct ucred *cred, struct vnode *vp, 
	              struct label *vplabel, mode_t mode)
{
	return (sip_check_filepath(vp));
}

static int
sip_check_setowner(struct ucred *cred, struct vnode *vp, 
	               struct label *vplabel, uid_t uid, gid_t gid)
{
	return (sip_check_filepath(vp));
}

static int
sip_check_setutimes(struct ucred *cred, struct vnode *vp, struct label *vplabel,
		            struct timespec atime, struct timespec mtime)
{
	return (sip_check_filepath(vp));
}

static int
sip_check_unlink(struct ucred *cred, struct vnode *dvp, struct label *dvplabel,
		         struct vnode *vp, struct label *vplabel, struct componentname *cnp)
{
	return (sip_check_dirpath(dvp));
}

static int
sip_check_write(struct ucred *active_cred, struct ucred *file_cred, 
	            struct vnode *vp, struct label *vplabel)
{	
	return (sip_check_filepath(vp));
}

static int
sip_check_kld_load(struct ucred *cred, struct vnode *vp, struct label *vlabel)
{
    return (0);
}

static int
sip_check_debug(struct ucred *cred, struct proc *p)
{

	return (0);
}

static int
sip_check_sched(struct ucred *cred, struct proc *p)
{

	return (0);
}

static int
sip_check_signal(struct ucred *cred, struct proc *proc, int signum)
{

	return (0);
}

/* The MAC entry points we want to handle. */
static struct mac_policy_ops sip_ops = {

    /* Our Policy init and teardown functions. */
	.mpo_init = init_sip,
	.mpo_destroy = destroy_sip,

	/* Path related entry point checks. */
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
	.mpo_vnode_check_write = sip_check_write,

	/* Kernel module entry point checks. */
	.mpo_kld_check_load = sip_check_kld_load,

    /* Proccess entry point checks. */
	.mpo_proc_check_debug = sip_check_debug,
	.mpo_proc_check_sched = sip_check_sched,
	.mpo_proc_check_signal = sip_check_signal

};

/* Declare the MAC framework policy. */
MAC_POLICY_SET(&sip_ops, mac_sip, "System integrity protection",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
