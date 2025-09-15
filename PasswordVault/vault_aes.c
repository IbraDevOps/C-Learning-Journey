// vault_aes.c — AES-GCM + PBKDF2 password vault (portable, no getpass)
// Build: gcc -std=gnu99 -Wall -Wextra -Wpedantic -O2 -o vault_aes vault_aes.c crypto.c -lcrypto

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include "crypto.h"

/* --------- Vault format constants --------- */
#define MAGIC       "VAES1\n"
#define MAGIC_LEN   6

#define VAULT_FILE  "vault_aes.dat"

#define SALT_LEN    16
#define NONCE_LEN   12
#define TAG_LEN     16
#define KEY_LEN     32          /* AES-256 */
#define PBKDF2_ITERS 200000u     /* adjust to taste */

#define MAX_LINE    1024

/* --------- small utils --------- */
static void die(const char *m){ perror(m); exit(1); }

static char *xstrdup(const char *s){
    size_t n = strlen(s) + 1;
    char *p = (char*)malloc(n);
    if(!p) die("malloc");
    memcpy(p, s, n);
    return p;
}

/* Hidden password prompt (portable) */
static char *prompt_hidden(const char *prompt){
    static char buf[256];
    struct termios oldt, newt;

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    if(tcgetattr(STDIN_FILENO, &oldt) != 0) return NULL;
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) != 0) return NULL;

    if(!fgets(buf, sizeof buf, stdin)) return NULL;

    /* restore */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
    fprintf(stderr, "\n");

    buf[strcspn(buf, "\r\n")] = 0;
    return xstrdup(buf); /* caller frees */
}

/* --------- TSV lines in memory --------- */
typedef struct { char **rows; size_t len, cap; } Lines;

static void lines_push(Lines *L, const char *line){
    if(L->len == L->cap){
        size_t nc = L->cap ? L->cap * 2 : 8;
        char **p = (char**)realloc(L->rows, nc * sizeof *p);
        if(!p) die("realloc");
        L->rows = p; L->cap = nc;
    }
    L->rows[L->len++] = xstrdup(line);
}

static void lines_free(Lines *L){
    for(size_t i=0;i<L->len;i++) free(L->rows[i]);
    free(L->rows);
    L->rows=NULL; L->len=L->cap=0;
}

/* Serialize lines -> single plaintext blob (with header) */
static unsigned char *serialize(const Lines *L, size_t *outlen){
    const char *hdr = "# AES_VAULT (authenticated)\n";
    size_t total = strlen(hdr);
    for(size_t i=0;i<L->len;i++) total += strlen(L->rows[i]) + 1;

    unsigned char *buf = (unsigned char*)malloc(total + 1);
    if(!buf) die("malloc");

    size_t off = 0;
    memcpy(buf+off, hdr, strlen(hdr)); off += strlen(hdr);
    for(size_t i=0;i<L->len;i++){
        size_t n = strlen(L->rows[i]);
        memcpy(buf+off, L->rows[i], n); off += n;
        buf[off++] = '\n';
    }
    buf[off] = '\0';
    *outlen = off;
    return buf;
}

/* Parse plaintext blob -> lines (skip header lines starting with '#') */
static void parse_lines(Lines *L, char *plain){
    L->rows=NULL; L->len=L->cap=0;
    char *save=NULL;
    for(char *tok = strtok_r(plain, "\n", &save); tok; tok = strtok_r(NULL, "\n", &save)){
        if(tok[0] == '#') continue;
        if(*tok) lines_push(L, tok);
    }
}

/* --------- file I/O helpers --------- */
static int file_exists(const char *p){ struct stat st; return stat(p,&st)==0; }

static unsigned char *read_all(const char *path, size_t *sz){
    FILE *f = fopen(path, "rb");
    if(!f){ *sz=0; return NULL; }
    if(fseek(f,0,SEEK_END)!=0) die("fseek");
    long m = ftell(f); if(m < 0) die("ftell");
    rewind(f);
    unsigned char *buf = (unsigned char*)malloc((size_t)m);
    if(!buf) die("malloc");
    if(fread(buf,1,(size_t)m,f)!=(size_t)m) die("fread");
    fclose(f);
    *sz = (size_t)m;
    return buf;
}

static void write_all_atomic(const char *path, const uint8_t *data, size_t n){
    char tmp[256]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "wb"); if(!f) die("fopen tmp");
    if(fwrite(data,1,n,f)!=n) die("fwrite");
    if(fclose(f)!=0) die("fclose");
    if(rename(tmp, path)!=0) die("rename");
    chmod(path, 0600); /* owner-only perms */
}

/* --------- AES-GCM vault read/write --------- */
/* Layout:
   MAGIC(6) |
   iters(4 LE) |
   salt(16) |
   nonce(12) |
   ct_len(4 LE) |
   ciphertext(ct_len) |
   tag(16)
*/

static void save_vault(const Lines *L, const char *password){
    /* generate fresh salt + nonce each save */
    uint8_t salt[SALT_LEN];
    uint8_t nonce[NONCE_LEN];
    if(crypto_rand(salt, SALT_LEN)!=0)  die("RAND(salt)");
    if(crypto_rand(nonce, NONCE_LEN)!=0) die("RAND(nonce)");

    /* serialize */
    size_t plen=0; unsigned char *plain = serialize(L, &plen);

    /* derive key */
    uint8_t key[KEY_LEN];
    if(kdf_pbkdf2_sha256(password, salt, SALT_LEN, PBKDF2_ITERS, key, KEY_LEN)!=0){
        fprintf(stderr, "KDF failed\n"); exit(1);
    }

    /* encrypt */
    uint8_t *ct = (uint8_t*)malloc(plen); if(!ct) die("malloc");
    uint8_t tag[TAG_LEN];
    if(aes256gcm_encrypt(key, nonce, NONCE_LEN,
                         plain, plen,
                         NULL, 0,
                         ct, tag, TAG_LEN) != 0){
        fprintf(stderr, "encrypt failed\n"); exit(1);
    }

    /* assemble file */
    uint32_t iters_le = PBKDF2_ITERS; /* host LE assumed */
    uint32_t ct_len_le = (uint32_t)plen;

    size_t outsz = MAGIC_LEN + 4 + SALT_LEN + NONCE_LEN + 4 + (size_t)ct_len_le + TAG_LEN;
    uint8_t *out = (uint8_t*)malloc(outsz); if(!out) die("malloc");

    size_t off=0;
    memcpy(out+off, MAGIC, MAGIC_LEN); off+=MAGIC_LEN;
    memcpy(out+off, &iters_le, 4);     off+=4;
    memcpy(out+off, salt, SALT_LEN);   off+=SALT_LEN;
    memcpy(out+off, nonce, NONCE_LEN); off+=NONCE_LEN;
    memcpy(out+off, &ct_len_le, 4);    off+=4;
    memcpy(out+off, ct, ct_len_le);    off+=ct_len_le;
    memcpy(out+off, tag, TAG_LEN);     off+=TAG_LEN;

    write_all_atomic(VAULT_FILE, out, outsz);

    /* scrub */
    secure_bzero(key, KEY_LEN);
    secure_bzero(plain, plen); free(plain);
    secure_bzero(ct, plen);    free(ct);
    secure_bzero(out, outsz);  free(out);
}

static void load_vault(Lines *L, const char *password){
    size_t sz=0;
    uint8_t *buf = read_all(VAULT_FILE, &sz);
    if(!buf){ fprintf(stderr, "No vault. Run: ./vault_aes init\n"); exit(1); }
    if(sz < MAGIC_LEN || memcmp(buf, MAGIC, MAGIC_LEN)!=0){
        fprintf(stderr, "Not an AES vault (bad magic)\n"); exit(1);
    }
    size_t off = MAGIC_LEN;
    if(sz < off + 4 + SALT_LEN + NONCE_LEN + 4 + TAG_LEN){
        fprintf(stderr, "Corrupt vault (too small)\n"); exit(1);
    }

    uint32_t iters; memcpy(&iters, buf+off, 4); off+=4;
    uint8_t salt[SALT_LEN]; memcpy(salt, buf+off, SALT_LEN); off+=SALT_LEN;
    uint8_t nonce[NONCE_LEN]; memcpy(nonce, buf+off, NONCE_LEN); off+=NONCE_LEN;
    uint32_t ct_len; memcpy(&ct_len, buf+off, 4); off+=4;

    if(sz < off + (size_t)ct_len + TAG_LEN){
        fprintf(stderr, "Corrupt vault (ct overrun)\n"); exit(1);
    }
    uint8_t *ct = buf+off; off += ct_len;
    uint8_t tag[TAG_LEN]; memcpy(tag, buf+off, TAG_LEN); off+=TAG_LEN;

    uint8_t key[KEY_LEN];
    if(kdf_pbkdf2_sha256(password, salt, SALT_LEN, iters, key, KEY_LEN)!=0){
        fprintf(stderr, "KDF failed\n"); exit(1);
    }

    unsigned char *plain = (unsigned char*)malloc((size_t)ct_len + 1);
    if(!plain) die("malloc");

    if(aes256gcm_decrypt(key, nonce, NONCE_LEN,
                         ct, ct_len,
                         NULL, 0,
                         tag, TAG_LEN,
                         plain) != 0){
        secure_bzero(key, KEY_LEN);
        secure_bzero(plain, ct_len); free(plain);
        secure_bzero(buf, sz); free(buf);
        fprintf(stderr, "Wrong master password or vault has been tampered.\n");
        exit(1);
    }
    plain[ct_len] = '\0';

    parse_lines(L, (char*)plain);

    secure_bzero(key, KEY_LEN);
    secure_bzero(plain, ct_len); free(plain);
    secure_bzero(buf, sz); free(buf);
}

/* --------- commands --------- */

static int cmd_init(void){
    if(file_exists(VAULT_FILE)){
        fprintf(stderr, "Refusing to overwrite existing %s\n", VAULT_FILE);
        return 1;
    }
    char *pw1 = prompt_hidden("Set master password: ");
    char *pw2 = prompt_hidden("Confirm master password: ");
    if(!pw1 || !pw2){ fprintf(stderr,"password input failed\n"); return 1; }
    if(strcmp(pw1,pw2)!=0){
        fprintf(stderr, "Passwords do not match.\n");
        secure_bzero(pw1, strlen(pw1));
        secure_bzero(pw2, strlen(pw2));
        free(pw1); free(pw2);
        return 1;
    }

    Lines L = {0}; /* empty vault */
    save_vault(&L, pw1);

    secure_bzero(pw1, strlen(pw1));
    secure_bzero(pw2, strlen(pw2));
    free(pw1); free(pw2);
    lines_free(&L);

    printf("Initialized AES vault: %s\n", VAULT_FILE);
    return 0;
}

static int cmd_add(const char *svc, const char *usr, const char *pwd){
    if(!svc||!usr||!pwd){
        fprintf(stderr,"Usage: vault_aes add --service S --user U --pass P\n");
        return 1;
    }
    if(strchr(svc,'\t')||strchr(usr,'\t')||strchr(pwd,'\t')||
       strchr(svc,'\n')||strchr(usr,'\n')||strchr(pwd,'\n')){
        fprintf(stderr,"Tabs/newlines not allowed in fields.\n");
        return 1;
    }

    char *pw = prompt_hidden("Master password: ");
    if(!pw){ fprintf(stderr,"password input failed\n"); return 1; }

    Lines L; load_vault(&L, pw);

    char line[MAX_LINE];
    snprintf(line, sizeof line, "%s\t%s\t%s", svc, usr, pwd);
    lines_push(&L, line);

    save_vault(&L, pw);

    secure_bzero(pw, strlen(pw)); free(pw);
    lines_free(&L);
    printf("Added entry for service: %s\n", svc);
    return 0;
}

static int cmd_list(void){
    char *pw = prompt_hidden("Master password: ");
    if(!pw){ fprintf(stderr,"password input failed\n"); return 1; }

    Lines L; load_vault(&L, pw);
    for(size_t i=0;i<L.len;i++){
        char buf[MAX_LINE]; strncpy(buf, L.rows[i], sizeof buf); buf[sizeof buf-1]=0;
        char *svc = strtok(buf, "\t");
        if(svc) puts(svc);
    }
    secure_bzero(pw, strlen(pw)); free(pw);
    lines_free(&L);
    return 0;
}

static int cmd_show(const char *svc_q){
    if(!svc_q){
        fprintf(stderr,"Usage: vault_aes show --service S\n");
        return 1;
    }
    char *pw = prompt_hidden("Master password: ");
    if(!pw){ fprintf(stderr,"password input failed\n"); return 1; }

    Lines L; load_vault(&L, pw);
    int found=0;
    for(size_t i=0;i<L.len;i++){
        char buf[MAX_LINE]; strncpy(buf, L.rows[i], sizeof buf); buf[sizeof buf-1]=0;
        char *svc = strtok(buf, "\t");
        char *usr = strtok(NULL, "\t");
        char *pwd = strtok(NULL, "\t");
        if(svc && usr && pwd && strcmp(svc, svc_q)==0){
            printf("service : %s\nuser    : %s\npass    : %s\n", svc, usr, pwd);
            found=1; break;
        }
    }
    if(!found) fprintf(stderr, "No entry found for service: %s\n", svc_q);

    secure_bzero(pw, strlen(pw)); free(pw);
    lines_free(&L);
    return found?0:1;
}

/* --------- main --------- */
int main(int argc, char **argv){
    if(argc < 2){
        fprintf(stderr,
            "Usage:\n"
            "  vault_aes init\n"
            "  vault_aes add --service S --user U --pass P\n"
            "  vault_aes list\n"
            "  vault_aes show --service S\n");
        return 1;
    }
    if(strcmp(argv[1],"init")==0) return cmd_init();
    if(strcmp(argv[1],"add")==0){
        const char *svc=NULL,*usr=NULL,*pwd=NULL;
        for(int i=2;i<argc;i++){
            if(strcmp(argv[i],"--service")==0 && i+1<argc) svc=argv[++i];
            else if(strcmp(argv[i],"--user")==0 && i+1<argc) usr=argv[++i];
            else if(strcmp(argv[i],"--pass")==0 && i+1<argc) pwd=argv[++i];
        }
        return cmd_add(svc,usr,pwd);
    }
    if(strcmp(argv[1],"list")==0) return cmd_list();
    if(strcmp(argv[1],"show")==0){
        const char *svc=NULL;
        for(int i=2;i<argc;i++){
            if(strcmp(argv[i],"--service")==0 && i+1<argc) svc=argv[++i];
        }
        return cmd_show(svc);
    }
    fprintf(stderr,"Unknown command: %s\n", argv[1]);
    return 1;
}
