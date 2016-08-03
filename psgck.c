/*
 * Copyright © 2016 Lars Lindqvist
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <grp.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <regex.h>
#include <unistd.h>

#include <arg.h>

static const char default_passwd_file[] = "/etc/passwd";
static const char default_group_file[]  = "/etc/group";
static const char default_shadow_file[] = "/etc/shadow";
static const char default_name_regex_str[] = "^[a-z][0-9a-z]*$";

struct entry {
	char *name;
	long id;
	struct entry *next;
};

struct checker {
	size_t toks;
	size_t name_tok;
	size_t id_tok;
	const char *path;
	struct entry *head;
	bool (*checker1)(char**);
	bool (*checker2)(char**);
};

enum pass { PASS_FIRST, PASS_SECOND };
enum { GR_NAME = 0, GR_PASSWD, GR_GID, GR_USERS, GR_LAST };
enum { PW_NAME = 0, PW_PASSWD, PW_UID, PW_GID, PW_COMMENT, PW_HOME, PW_SHELL, PW_LAST };
enum { SP_NAME = 0, SP_PASSWD, SP_CHANGED, SP_MIN, SP_MAX, SP_WARN, SP_INACT, SP_EXPIRE, SP_RESERVED, SP_LAST };

static bool check_group(char**);
static bool check_group2(char**);
static bool check_shadow(char**);
static bool check_shadow2(char**);
static bool check_passwd(char**);
static bool check_passwd2(char**);

static struct checker pwdck = {
	PW_LAST, PW_NAME, PW_UID, default_passwd_file, NULL, check_passwd, check_passwd2
};

static struct checker grpck = {
	GR_LAST, GR_NAME, GR_GID, default_group_file, NULL, check_group, check_group2
};

static struct checker spwck = {
	SP_LAST, SP_NAME, -1, default_shadow_file, NULL, check_shadow, check_shadow2
};

static regex_t name_regex;
static int pedanticness = 0;

static void
usage() {
	printf("usage: %s [-vvv] [-n name-pattern] [-p passwd] [-s shadow] [-g group]\n", argv0);
	exit(1);
}

static struct entry*
find_id(struct entry *head, long id) {
	struct entry *e;

	for (e = head; e; e = e->next) {
		if (e->id == id) {
			return e;
		}
	}
	return NULL;
}

static struct entry*
find_name(struct entry *head, char *name) {
	struct entry *e;

	for (e = head; e; e = e->next) {
		if (strcmp(e->name, name) == 0) {
			return e;
		}
	}
	return NULL;
}

static bool
check_name(const char *name) {
	size_t len;
	
	len = strlen(name);

	if (len == 0)
		return false;

	if (regexec(&name_regex, name, 0, NULL, 0) == REG_NOMATCH)
		return false;

	return true;
}

static bool
onlydigits(const char *str) {
	size_t i, len;

	len = strlen(str);

	for (i = 0; i < len; ++i) {
		if (!isdigit(str[i]))
			return false;
	}
	return true;

}

static long
parse_id(const char *id) {
	if (!id)
		return -1;
	if (id[0] == '\0')
		return -1;
	if (!onlydigits(id))
		return -1;
	return atol(id);
}

static bool
check_passwd(char **toks) {
	struct checker *ck = &pwdck;
	struct entry *e;
	bool ok = true;

	char *name = toks[PW_NAME];
	char *passwd = toks[PW_PASSWD]; 
	char *uid_s = toks[PW_UID];
	char *gid_s = toks[PW_GID];
	char *comment = toks[PW_COMMENT];
	char *home = toks[PW_HOME];
	char *shell = toks[PW_SHELL];
	uid_t uid;
	gid_t gid;

	if (!check_name(name)) {
		printf("%s: %s: illegal username.\n", ck->path, name);
		ok = false;
	}

	/* FIXME ? */
	(void)passwd;

	if ((uid = parse_id(uid_s)) == (uid_t)-1) {
		printf("%s: %s: invalid uid '%s'\n", ck->path, name, uid_s);
		ok = false;
	}

	if ((gid = parse_id(gid_s)) == (gid_t)-1) {
		printf("%s: %s: invalid gid '%s'\n", ck->path, name, gid_s);
		ok = false;
	}

	/* uniqueness */
	if (pedanticness > 0) {
		if ((e = find_id(pwdck.head, uid))) {
			printf("%s: %s: shares uid '%d' with %s\n",
			       ck->path, name, uid, e->name);
			ok = false;
		}
	}

	if ((e = find_name(pwdck.head, name))) {
		printf("%s: %s: duplicate name, uids: '%d' and '%ld'\n",
		       ck->path, name, uid, e->id);
		ok = false;
	}

	/* FIXME ? */
	(void)comment;

	/* check home */
	if (home[0] == '\0') {
		printf("%s: %s: empty home directory\n", ck->path, name);
		ok = false;
	}
	else if (home[0] != '/') {
		printf("%s: %s: home '%s' not absolute\n", ck->path, name, home);
		ok = false;
	}
	else if (access(home, F_OK) == -1) {
		if (pedanticness > 0 || errno == EACCES && pedanticness > 1) { 
			printf("%s: %s: home '%s' missing: %s\n",
			       ck->path, name, home, strerror(errno));
			ok = false;
		}
	}

	/* check shell */
	if (shell[0] == '\0') {
		if (pedanticness > 0) {
			printf("%s: %s: empty shell\n", ck->path, name);
			ok = false;
		}
	}
	else if (shell[0] != '/') {
		printf("%s: %s: shell '%s' not absolute\n", ck->path, name, shell);
		ok = false;
	}
	else if (access(shell, F_OK) == -1) {
		printf("%s: %s: shell '%s' missing: %s\n",
		       ck->path, name, shell, strerror(errno));
		ok = false;
	}

	return ok;
}

static bool
check_passwd2(char **toks) {
	struct checker *ck = &pwdck;
	bool ok = true;

	char *name = toks[PW_NAME];
	char *passwd = toks[PW_PASSWD]; 
	char *gid_s = toks[PW_GID];
	gid_t gid;

	if (passwd[0] == 'x' && passwd[1] == '\0') {
		/* shadow must have corresponding entry */
		if (!find_name(spwck.head, name)) {
			printf("%s: %s: missing from %s\n", ck->path, name, spwck.path);
			ok = false;
		}
	}

	if ((gid = parse_id(gid_s)) == (gid_t)-1) {
		ok = false;
	} else {
		/* primary group must exist */
		if (!find_id(grpck.head, gid)) {
			printf("%s: %s: group '%d' missing from %s\n",
			       ck->path, name, gid, grpck.path);
			ok = false;
		}
	}

	return ok;
}


/* verify shadow name, uniqueness and dates */
static bool
check_shadow(char **toks) {
	struct checker *ck = &spwck;
	bool ok = true;
	char *name = toks[SP_NAME];
	long int now;

	long int sp_changed = -1;
	long int sp_min = -1;
	long int sp_max = -1;
	long int sp_warn = -1;
	long int sp_inact = -1;
	long int sp_expire = -1;

	if (!check_name(name)) {
		printf("%s: %s: illegal username.\n", ck->path, name);
		ok = false;
	}

	if (find_name(spwck.head, name)) {
		printf("%s: %s: duplicate entry\n", ck->path, name);
		ok = false;
	}


#define SP_DIGITCHECK(i, var, msg)      do { (void)var;                    \
	if (onlydigits(toks[(i)])) {                                       \
		var  = toks[(i)][0] == '\0' ? -1 : atol(toks[(i)]);        \
	} else {                                                           \
		ok = false;                                                \
		printf("%s: %s: non-digit " msg  " '%s'\n",                \
		       ck->path, name, toks[(i)]);                         \
	} } while(0)


	SP_DIGITCHECK(SP_CHANGED, sp_changed, "last-changed");
	SP_DIGITCHECK(SP_MIN,     sp_min,     "minimum-age");
	SP_DIGITCHECK(SP_MAX,     sp_max,     "maximum-age");
	SP_DIGITCHECK(SP_WARN,    sp_warn,    "warning-period");
	SP_DIGITCHECK(SP_INACT,   sp_inact,   "inactivity-period");
	SP_DIGITCHECK(SP_EXPIRE,  sp_expire,  "expiration-date");

#undef SP_DIGITCHECK

	if (sp_expire == 0) {
		printf("%s: %s: expiration-date '0' ambiguous, 1970-01-01 or never\n",
		       ck->path, name);
		ok = false;
	}

	if (pedanticness > 1) {
		now = time(NULL) / (24L * 60L * 60L);

		if (sp_changed != -1 && sp_changed > now) {
			printf("%s: %s: last-changed is %ld days in the future\n",
			       ck->path, name, sp_changed - now);
			ok = false;
		}

		if (sp_expire != -1 && sp_expire > now) {
			printf("%s: %s: account expired %ld days ago\n",
			       ck->path, name, sp_expire - now);
			ok = false;
		}
	}

	if (pedanticness > 2) {
		if (sp_changed == 0
		||  sp_max != -1 && sp_changed > 0 && sp_changed + sp_max < now) {
			printf("%s: %s: user needs to change password\n", ck->path, name);
			ok = false;
		}
		if (sp_min != -1 && sp_max != -1 && sp_max < sp_min) {
			printf("%s: %s: user cannot change password\n", ck->path, name);
			ok = false;
		}
		if (sp_min > 0 && sp_changed > 0 && sp_changed + sp_min > now) {
			printf("%s: %s: password too young to change\n", ck->path, name);
			ok = false;
		}
	}


	return ok;
}

/* verify that users exist */
static bool
check_shadow2(char **toks) {
	bool ok = true;
	struct checker *ck = &spwck;
	char *name = toks[SP_NAME];

	if (!find_name(pwdck.head, toks[SP_NAME])) {
		printf("%s: %s: user does not exist\n", ck->path, name);
		ok = false;
	}

	return ok;
}

/* verify name and gid, and their uniqueness */
static bool
check_group(char **toks) {
	struct checker *ck = &grpck;
	struct entry *e;
	bool ok = true;

	char *name = toks[GR_NAME];
	char *gid_s = toks[GR_GID];
	gid_t gid;

	if (!check_name(name)) {
		printf("%s: %s: illegal username.\n", ck->path, name);
		ok = false;
	}

	if ((gid = parse_id(gid_s)) == (gid_t)-1) {
		printf("%s: %s: invalid uid '%s'\n", ck->path, name, gid_s);
		ok = false;
	}

	if ((e = find_name(grpck.head, name))) {
		printf("%s: %s: duplicate name, gids: '%d' and '%ld'\n",
		       ck->path, name, gid, e->id);
		ok = false;
	}

	if ((e = find_id(grpck.head, gid))) {
		printf("%s: %s: shares gid '%d' with '%s'\n",
		       ck->path, name, gid, e->name);
		ok = false;
	}

	return ok;
}

/* second pass at groups: ∨erify members */
static bool
check_group2(char **toks) {
	struct checker *ck = &grpck;
	bool ok = true;
	size_t n;
	char *sep;
	char *tok;

	char *name= toks[GR_NAME];

	if (toks[GR_USERS][0] == '\0')
		return true;

	for (tok = toks[GR_USERS], n = 0; tok; ++n, tok = sep ? sep + 1 : NULL) {
		if ((sep = strchr(tok, ',')))
			*sep = '\0';

		if (!check_name(tok)) {
			printf("%s: %s: invalid user name '%s'\n", ck->path, name, tok);
			ok = false;
		} else {
			if (!find_name(pwdck.head, tok)) {
				printf("%s: %s: member '%s' does not exist\n",
				       ck->path, name, tok);
				ok = false;
			}
		}
	}


	return ok;
}

static bool
check(struct checker *ck, enum pass pass) {
	bool ok = true;
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t bytes;

	if (!(fp = fopen(ck->path, "r"))) {
		if (pass == PASS_FIRST)
			fprintf(stderr, "%s: ERROR: fopen %s: %s\n",
			        argv0, ck->path, strerror(errno));
		return false;
	}

	while ((bytes = getline(&line, &len, fp)) > 0) {
		bool ent_ok = true;
		char **toks;
		char *tok;
		char *sep;
		size_t n;

		char *name = NULL;
		long id = -1;

		if (bytes > 0 && line[bytes - 1] == '\n') {
			line[bytes - 1] = '\0';
		}

		toks = calloc(ck->toks, sizeof(char*));

		for (tok = line, n = 0; tok; ++n, tok = sep ? sep + 1 : NULL) {
			if ((sep = strchr(tok, ':')))
				*sep = '\0';

			if (n == ck->name_tok)
				name = tok;
			else if (n == ck->id_tok)
				id = atol(tok);

			if (n < ck->toks) {
				toks[n] = tok;
			} else {
				if (pass == PASS_FIRST)
					printf("%s: %s: superfluous %luth token '%s'\n",
					       ck->path, name, n, tok);
				ent_ok = false;
			}
		}

		if (n < ck->toks) {
			if (pass == PASS_FIRST)
				printf("%s: %s: missing %lu tokens\n",
				       ck->path, name, ck->toks - n);
			ent_ok = false;
		}

		if (ent_ok) {
			if (pass == PASS_FIRST) {
				struct entry *e;

				if (!ck->checker1(toks)) {
					ok = false;
				}

				e = malloc(sizeof(struct entry));
				e->name = strdup(name);
				e->id = id;
				e->next = ck->head;
				ck->head = e;

			}
			else {
				if (!ck->checker2(toks)) {
					ok = false;
				}
			}

		} else {
			ok = false;
		}

		free(toks);

	}
	if (!feof(fp)) {
		if (pass == PASS_FIRST)
			fprintf(stderr, "%s: ERROR: getline %s: %s\n",
			        argv0, ck->path, strerror(errno));
		ok = false;
	}

	free(line);

	fclose(fp);

	return ok;
}

void
free_list(struct entry *head) {
	while (head) {
		struct entry *e;

		e = head->next;
		free(head->name);
		free(head);
		head = e;
	}
}

int
main(int argc, char *argv[]) {
	int err = 0;
	const char *name_regex_str = default_name_regex_str;


	ARGBEGIN {
	case 'v':
		++pedanticness;
		break;
	case 'p':
		pwdck.path = EARGF(usage());
		break;
	case 's':
		spwck.path = EARGF(usage());
		break;
	case 'g':
		grpck.path = EARGF(usage());
		break;
	case 'n':
		name_regex_str = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND;

	if (argc)
		usage();

	if (regcomp(&name_regex, name_regex_str, REG_EXTENDED)) {
		fprintf(stderr, "%s: FATAL: invalid regex %s\n", argv0, name_regex_str);
		return 1;
	}

	if (!check(&grpck, PASS_FIRST))
		err = 1;
	if (!check(&spwck, PASS_FIRST))
		err = 1;
	if (!check(&pwdck, PASS_FIRST))
		err = 1;
	if (!check(&grpck, PASS_SECOND))
		err = 1;
	if (!check(&spwck, PASS_SECOND))
		err = 1;
	if (!check(&pwdck, PASS_SECOND))
		err = 1;

	free_list(pwdck.head);
	free_list(grpck.head);
	free_list(spwck.head);

	regfree(&name_regex);

	return err;
}
