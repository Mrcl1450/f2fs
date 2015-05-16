/*
 * General per-file encryption definition
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * Written by Michael Halcrow, 2015.
 * Modified by Jaegeuk Kim, 2015.
 */

#ifndef _LINUX_FSCRYPTO_H
#define _LINUX_FSCRYPTO_H

#include <linux/key.h>

#define FS_KEY_DESCRIPTOR_SIZE	8

/* Policy provided via an ioctl on the topmost directory */
struct fscrypt_policy {
	char version;
	char contents_encryption_mode;
	char filenames_encryption_mode;
	char flags;
	char master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
} __packed;

#define FS_ENCRYPTION_CONTEXT_FORMAT_V1		1
#define FS_KEY_DERIVATION_NONCE_SIZE		16

#define FS_POLICY_FLAGS_PAD_4		0x00
#define FS_POLICY_FLAGS_PAD_8		0x01
#define FS_POLICY_FLAGS_PAD_16		0x02
#define FS_POLICY_FLAGS_PAD_32		0x03
#define FS_POLICY_FLAGS_PAD_MASK	0x03
#define FS_POLICY_FLAGS_VALID		0x03

/* Encryption algorithms */
#define FS_ENCRYPTION_MODE_INVALID		0
#define FS_ENCRYPTION_MODE_AES_256_XTS		1
#define FS_ENCRYPTION_MODE_AES_256_GCM		2
#define FS_ENCRYPTION_MODE_AES_256_CBC		3
#define FS_ENCRYPTION_MODE_AES_256_CTS		4

/**
 * Encryption context for inode
 *
 * Protector format:
 *  1 byte: Protector format (1 = this version)
 *  1 byte: File contents encryption mode
 *  1 byte: File names encryption mode
 *  1 byte: Flags
 *  8 bytes: Master Key descriptor
 *  16 bytes: Encryption Key derivation nonce
 */
struct fscrypt_context {
	char format;
	char contents_encryption_mode;
	char filenames_encryption_mode;
	char flags;
	char master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
	char nonce[FS_KEY_DERIVATION_NONCE_SIZE];
} __packed;

/* Encryption parameters */
#define FS_XTS_TWEAK_SIZE		16
#define FS_AES_128_ECB_KEY_SIZE		16
#define FS_AES_256_GCM_KEY_SIZE		32
#define FS_AES_256_CBC_KEY_SIZE		32
#define FS_AES_256_CTS_KEY_SIZE		32
#define FS_AES_256_XTS_KEY_SIZE		64
#define FS_MAX_KEY_SIZE			64

#define FS_KEY_DESC_PREFIX		"fscrypt:"
#define FS_KEY_DESC_PREFIX_SIZE		8

/* This is passed in from userspace into the kernel keyring */
struct fscrypt_key {
	__u32 mode;
	char raw[FS_MAX_KEY_SIZE];
	__u32 size;
} __packed;

struct fscrypt_info {
	char ci_data_mode;
	char ci_filename_mode;
	char ci_flags;
	struct crypto_ablkcipher *ci_ctfm;
	struct key *ci_keyring_key;
	char ci_master_key[FS_KEY_DESCRIPTOR_SIZE];
};

#define FS_CTX_REQUIRES_FREE_ENCRYPT_FL		0x00000001
#define FS_WRITE_PATH_FL			0x00000002

struct fscrypt_ctx {
	union {
		struct {
			struct page *bounce_page;	/* Ciphertext page */
			struct page *control_page;	/* Original page  */
		} w;
		struct {
			struct bio *bio;
			struct work_struct work;
		} r;
		struct list_head free_list;	/* Free list */
	};
	char flags;				/* Flags */
	char mode;				/* Encryption mode for tfm */
};

struct fscrypt_completion_result {
	struct completion completion;
	int res;
};

#define DECLARE_FS_COMPLETION_RESULT(ecr) \
	struct fscrypt_completion_result ecr = { \
		COMPLETION_INITIALIZER((ecr).completion), 0 }

static inline int fscrypt_key_size(int mode)
{
	switch (mode) {
	case FS_ENCRYPTION_MODE_AES_256_XTS:
		return FS_AES_256_XTS_KEY_SIZE;
	case FS_ENCRYPTION_MODE_AES_256_GCM:
		return FS_AES_256_GCM_KEY_SIZE;
	case FS_ENCRYPTION_MODE_AES_256_CBC:
		return FS_AES_256_CBC_KEY_SIZE;
	case FS_ENCRYPTION_MODE_AES_256_CTS:
		return FS_AES_256_CTS_KEY_SIZE;
	default:
		BUG();
	}
	return 0;
}

#define FS_FNAME_NUM_SCATTER_ENTRIES	4
#define FS_CRYPTO_BLOCK_SIZE		16
#define FS_FNAME_CRYPTO_DIGEST_SIZE	32

/**
 * For encrypted symlinks, the ciphertext length is stored at the beginning
 * of the string in little-endian format.
 */
struct fs_encrypted_symlink_data {
	__le16 len;
	char encrypted_path[1];
} __packed;

/**
 * This function is used to calculate the disk space required to
 * store a filename of length l in encrypted symlink format.
 */
static inline u32 encrypted_symlink_data_len(u32 l)
{
	if (l < FS_CRYPTO_BLOCK_SIZE)
		l = FS_CRYPTO_BLOCK_SIZE;
	return (l + sizeof(struct fs_encrypted_symlink_data) - 1);
}

struct fscrypt_str {
	unsigned char *name;
	u32 len;
};

struct fscrypt_name {
	const struct qstr *usr_fname;
	struct fscrypt_str disk_name;
	u32 hash;
	u32 minor_hash;
#ifdef CONFIG_FS_ENCRYPTION
	struct fscrypt_str crypto_buf;
#endif
};

#define FSTR_INIT(n, l)		{ .name = n, .len = l }
#define FSTR_TO_QSTR(f)		QSTR_INIT((f)->name, (f)->len)
#define fname_name(p)		((p)->disk_name.name)
#define fname_len(p)		((p)->disk_name.len)

/*
 * crypto opertions for filesystems
 */
struct fscrypt_operations {
	int (*get_context)(struct inode *, void *, size_t, void *);
	int (*set_context)(struct inode *, const void *, size_t, int, void *);
	bool (*is_encrypted)(struct inode *);
	bool (*empty_dir)(struct inode *);
	unsigned (*max_namelen)(struct inode *);
};

static inline bool fscrypt_valid_contents_enc_mode(uint32_t mode)
{
	return (mode == FS_ENCRYPTION_MODE_AES_256_XTS);
}

static inline bool fscrypt_valid_filenames_enc_mode(uint32_t mode)
{
	return (mode == FS_ENCRYPTION_MODE_AES_256_CTS);
}

static inline uint32_t fscrypt_validate_encryption_key_size(uint32_t mode,
							uint32_t size)
{
	if (size == fscrypt_key_size(mode))
		return size;
	return 0;
}

static inline uint32_t fscrypt_blocksize_round_up(size_t size, size_t blksize)
{
	return ((size + blksize - 1) / blksize) * blksize;
}

static inline bool fscrypt_is_dot_dotdot(const struct qstr *str)
{
	if (str->len == 1 && str->name[0] == '.')
		return true;

	if (str->len == 2 && str->name[0] == '.' && str->name[1] == '.')
		return true;

	return false;
}

/* crypto.c */
extern struct kmem_cache *fscrypt_info_cachep;

struct page *fscrypt_encrypt_page(struct inode *, struct page *);
int fscrypt_decrypt_page(struct inode *, struct page *);
int fscrypt_zeroout_range(struct inode *, pgoff_t, sector_t, unsigned int);
void fscrypt_end_io_crypto_work(struct fscrypt_ctx *, struct bio *);
struct fscrypt_ctx *fscrypt_get_ctx(struct inode *);
void fscrypt_release_ctx(struct fscrypt_ctx *);

#ifdef CONFIG_FS_ENCRYPTION
void fscrypt_restore_and_release_control_page(struct page **);
void fscrypt_restore_control_page(struct page *);

int fscrypt_initialize(void);
#else
static inline void fscrypt_restore_and_release_control_page(struct page **p) { }
static inline void fscrypt_restore_control_page(struct page *p) { }
#endif

/* policy.c */
int fscrypt_process_policy(struct inode *, const struct fscrypt_policy *);
int fscrypt_get_policy(struct inode *, struct fscrypt_policy *);
int fscrypt_has_permitted_context(struct inode *, struct inode *);
int fscrypt_inherit_context(struct inode *, struct inode *, void *);

/* keyinfo.c */
void fscrypt_put_encryption_info(struct inode *, struct fscrypt_info *);

#ifdef CONFIG_FS_ENCRYPTION
int get_crypt_info(struct inode *);
int fscrypt_get_encryption_info(struct inode *);

static inline int fscrypt_has_encryption_key(struct inode *inode)
{
	return (inode->i_crypt_info != NULL);
}
#else
static inline int fscrypt_get_encryption_info(struct inode *inode) { return 0; }
static inline int fscrypt_has_encryption_key(struct inode *inode) { return 0; }
#endif

/* fname.c */
int fscrypt_fname_crypto_alloc_buffer(struct inode *, u32,
			struct fscrypt_str *);
int fscrypt_fname_disk_to_usr(struct inode *, u32, u32,
			const struct fscrypt_str *, struct fscrypt_str *);
int fscrypt_fname_usr_to_disk(struct inode *, const struct qstr *,
			struct fscrypt_str *);

#ifdef CONFIG_FS_ENCRYPTION
void fscrypt_fname_free_buffer(struct fscrypt_str *);
void fscrypt_fname_free_filename(struct fscrypt_name *);
int fscrypt_fname_setup_filename(struct inode *, const struct qstr *,
				int lookup, struct fscrypt_name *);
#else
static inline void fscrypt_fname_free_buffer(struct fscrypt_str *p) { }
static inline void fscrypt_fname_free_filename(struct fscrypt_name *fname) { }

static inline int fscrypt_fname_setup_filename(struct inode *dir,
					const struct qstr *iname,
					int lookup, struct fscrypt_name *fname)
{
	memset(fname, 0, sizeof(struct fscrypt_name));
	fname->usr_fname = iname;
	fname->disk_name.name = (unsigned char *)iname->name;
	fname->disk_name.len = iname->len;
	return 0;
}
#endif
#endif	/* _LINUX_FSCRYPTO_H */
