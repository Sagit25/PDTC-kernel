/* Created by shyang */

#ifndef _PUZZLE_H
#define _PUZZLE_H

#include <linux/list.h>

#define PZLTYPE_NONE 0
#define PZLTYPE_EXT 1
#define PZLTYPE_BOT 2

#define BUCKET_SIZE 8192
#define HASH_FUNCTIONS 4
#define HASH_SALT 42

#define PLAIN_LENGTH 17
#define CBF_INPUT_LENGTH 8
#define SHA256_LENGTH 32

struct puzzle_policy {
	u32 ip;
	u32 seed;
	u32 length;
	u32 threshold;
	unsigned int table[BUCKET_SIZE];
	struct list_head list;
};

struct puzzle_cache {
	u32 ip;
	u32 dns_ip;
	u32 puzzle_type;
	u32 puzzle;
	u32 threshold;
	struct list_head list;
};

u32 do_hash_puzzle(u32 nonce, u32 seed, u32 dns_ip, u32 client_ip, u32 puzzle_type);
u32 do_solve_puzzle(u32 threshold, u32 puzzle, u32 dns_ip, u32 client_ip, u32 puzzle_type);
int find_puzzle_policy(u32 ip, struct puzzle_policy** ptr);
int find_puzzle_cache(u32 ip, struct puzzle_cache** ptr);
u32 update_to_new_seed(struct puzzle_policy* policy, u32 new_seed);
long add_policy(u32 ip, u32 threshold);
long update_policy(u32 ip, u32 seed, u32 threshold);
int do_check_puzzle(u32 type, u32 puzzle, u32 dns_ip, u32 nonce, u32 threshold, u32 policy_ip);
long do_get_threshold(u32 ip);
u32 do_set_threshold(u32 ip, u32 threshold);
u32 do_get_puzzle_type(void);
u32 do_set_puzzle_type(u32 type);
long do_get_local_dns(void);
long do_set_local_dns(u32 ip, u32 port);
/* CBF(Counting Bloom Filter) functions */
u32 hash_cbf(u32 salt, u32 x);
int insert_cbf(struct puzzle_policy* policy, u32 x);
int check_cbf(struct puzzle_policy* policy, u32 x);
int delete_cbf(struct puzzle_policy* policy, u32 x);

#endif
