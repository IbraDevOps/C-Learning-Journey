#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>   // for SIZE_MAX

typedef struct { char *ip; unsigned fails; } IPFail;
typedef struct { IPFail *data; size_t len, cap; } Vec;

static void *xmalloc(size_t n){
    void *p = malloc(n);
    if(!p){ perror("malloc"); exit(1); }
    return p;
}

static void *xrealloc(void *q, size_t n){
    void *p = realloc(q, n);
    if(!p){ perror("realloc"); exit(1); }
    return p;
}

static char *xstrdup(const char *s){
    size_t n = strlen(s)+1;
    char *p = (char*)xmalloc(n);
    memcpy(p,s,n);
    return p;
}

static void vec_reserve(Vec *v, size_t need){
    if(need <= v->cap) return;
    size_t nc = v->cap ? v->cap*2 : 16;
    while(nc < need){
        if(nc > SIZE_MAX/2){
            fprintf(stderr,"cap overflow\n");
            exit(1);
        }
        nc *= 2;
    }
    v->data = (IPFail*)xrealloc(v->data, nc*sizeof(IPFail));
    v->cap = nc;
}

static ssize_t vec_find_ip(Vec *v, const char *ip){
    for(size_t i=0;i<v->len;i++)
        if(strcmp(v->data[i].ip,ip)==0)
            return (ssize_t)i;
    return -1;
}

static void bump_ip(Vec *v,const char *ip){
    ssize_t i = vec_find_ip(v,ip);
    if(i<0){
        vec_reserve(v,v->len+1);
        v->data[v->len].ip = xstrdup(ip);
        v->data[v->len].fails = 1u;
        v->len++;
    } else {
        v->data[(size_t)i].fails++;
    }
}

static void vec_free(Vec *v){
    if(!v) return;
    for(size_t i=0;i<v->len;i++)
        free(v->data[i].ip);
    free(v->data);
    v->data=NULL;
    v->len=v->cap=0;
}

/* Extract IPv4 from journalctl-ish lines */
static int extract_ip(const char *line,char *out,size_t outsz){
    const char *p = strstr(line,"from ");
    if(!p) p = strstr(line,"rhost=");
    if(!p) return 0;

    p += (p[0]=='r')?6:5;
    size_t i=0;
    while(p[i] && (isdigit((unsigned char)p[i])||p[i]=='.')){
        if(i+1 >= outsz){
            return 0;
        }
        out[i]=p[i];
        i++;
    }

    if(i==0){
        const char *last = strrchr(line,' ');
        if(!last || !last[1]){
            return 0;
        }
        last++;
        size_t j=0;
        while(last[j] && (isdigit((unsigned char)last[j])||last[j]=='.')){
            if(j+1 >= outsz){
                return 0;
            }
            out[j]=last[j];
            j++;
        }
        if(j==0) return 0;
        out[j]='\0';
        return 1;
    }

    out[i]='\0';
    return 1;
}

/* --- enforcement helpers --- */
static bool is_whitelisted(const char *ip){
    // Keep only loopback whitelisted by default.
    return strcmp(ip,"127.0.0.1")==0;
}

static void ban_ip_nft(const char *ip, unsigned timeout_seconds){
    char cmd[256];
    snprintf(cmd,sizeof cmd,
             "nft add element inet filter mini_siem_blocklist { %s timeout %us }",
             ip, timeout_seconds);
    int rc = system(cmd);
    if(rc!=0) fprintf(stderr,"[enforce] nft add failed for %s (rc=%d)\n", ip, rc);
    else      fprintf(stderr,"[enforce] blocked %s for %us via nftables\n", ip, timeout_seconds);
}

static void usage(const char *prog){
    fprintf(stderr,
      "Usage: %s [--enforce] [--threshold=N] [--ban=SECONDS] [logfile]\n"
      "  Reads logfile or STDIN. Detects SSH brute-force, sudo failures, sudoers violations.\n"
      "  --enforce      add offending IPs to nftables set 'mini_siem_blocklist'\n"
      "  --threshold=N  fails needed to alert/ban (default 5)\n"
      "  --ban=SECONDS  nftables timeout (default 3600)\n", prog);
}

int main(int argc,char **argv){
    bool enforce=false;
    unsigned threshold=5;      /* default alert threshold */
    unsigned ban_seconds=3600; /* default ban time */

    const char *fname=NULL;
    for(int i=1;i<argc;i++){
        if     (strcmp(argv[i],"--enforce")==0) enforce=true;
        else if(strncmp(argv[i],"--threshold=",12)==0) threshold=(unsigned)atoi(argv[i]+12);
        else if(strncmp(argv[i],"--ban=",6)==0)        ban_seconds=(unsigned)atoi(argv[i]+6);
        else if(argv[i][0]=='-'){ usage(argv[0]); return 1; }
        else fname=argv[i];
    }

    FILE *fp = fname? fopen(fname,"r") : stdin;
    if(fname && !fp){ perror("fopen"); return 1; }

    Vec ssh_fails={0};
    unsigned long total=0, ssh_fail_lines=0, sudo_fail=0, sudo_notin=0;
    char line[4096];

    while(fgets(line,(int)sizeof line,fp)){
        total++;
        int is_sshd = strstr(line,"sshd")!=NULL;
        int is_sudo = strstr(line,"sudo")!=NULL;

        if(is_sshd && (strstr(line,"Failed password")||strstr(line,"Invalid user"))){
            ssh_fail_lines++;
            char ip[64]={0};
            if(extract_ip(line,ip,sizeof ip)) bump_ip(&ssh_fails,ip);
        }
        if(is_sudo && strstr(line,"authentication failure")) sudo_fail++;
        if(is_sudo && (strstr(line,"NOT in sudoers") ||
                       strstr(line,"is not in the sudoers file") ||
                       strstr(line,"not in the sudoers file"))) sudo_notin++;
    }
    if(fp!=stdin) fclose(fp);

    printf("\n== Mini SIEM (real logs) ==\n");
    printf("Total lines: %lu\n", total);
    printf("SSH failed log lines: %lu\n", ssh_fail_lines);
    printf("sudo auth failures: %lu\n", sudo_fail);
    printf("sudoers policy violations: %lu\n", sudo_notin);

    if(ssh_fail_lines){
        printf("\n-- SSH brute-force suspects (>= %u fails) --\n", threshold);
        for(size_t i=0;i<ssh_fails.len;i++){
            if(ssh_fails.data[i].fails >= threshold){
                printf("ALERT: %s has %u failed SSH attempts\n",
                       ssh_fails.data[i].ip, ssh_fails.data[i].fails);
                printf("  Remediation: fail2ban (sshd), key-only auth, disable root SSH, firewall allowlist.\n");
                if(enforce){
                    if(geteuid()!=0) {
                        fprintf(stderr,"[enforce] need root; run with sudo\n");
                    } else if(is_whitelisted(ssh_fails.data[i].ip)) {
                        fprintf(stderr,"[enforce] NOT banning %s (whitelisted)\n", ssh_fails.data[i].ip);
                    } else {
                        ban_ip_nft(ssh_fails.data[i].ip, ban_seconds);
                    }
                }
            }
        }
        if(!ssh_fails.len) printf("(no IPs extracted — check log format)\n");
    }

    if(ssh_fail_lines||sudo_fail||sudo_notin){
        printf("\n== Recommendations ==\n");
        if(ssh_fail_lines){
            printf("- Install & configure fail2ban for sshd\n");
        }
        if(sudo_fail)   printf("- Review sudo password policy; investigate repeated failures\n");
        if(sudo_notin)  printf("- Investigate users attempting sudo without authorization\n");
    }

    vec_free(&ssh_fails);
    return 0;
}
