#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VAULT_FILE "vault.txt"   /* plaintext for PART 1 ONLY */
#define MAX_LINE   1024

/* record = single credential line in the file: service\tusername\tpassword\n
   NOTE: plaintext now; we’ll encrypt the whole payload in Part 3. */

static void die(const char *msg){
    perror(msg);
    exit(1);
}

static int file_exists(const char *path){
    FILE *f = fopen(path, "r");
    if(!f) return 0;
    fclose(f);
    return 1;
}

/* init: create empty vault file (fail if exists to avoid clobber) */
static int cmd_init(void){
    if(file_exists(VAULT_FILE)){
        fprintf(stderr, "Refusing to overwrite existing %s\n", VAULT_FILE);
        return 1;
    }
    FILE *f = fopen(VAULT_FILE, "w");
    if(!f) die("fopen");
    /* could write a header comment to make clear this is Part 1 plaintext */
    fprintf(f, "# PART1_PLAINTEXT_VAULT (educational)\n");
    fclose(f);
    printf("Initialized empty vault: %s\n", VAULT_FILE);
    return 0;
}

/* add: append service, user, pass as one line (tab-separated) */
static int cmd_add(const char *service, const char *user, const char *pass){
    if(!service || !user || !pass){
        fprintf(stderr, "Usage: vault add --service S --user U --pass P\n");
        return 1;
    }
    FILE *f = fopen(VAULT_FILE, "a");
    if(!f) die("fopen");
    /* sanitize tabs/newlines in inputs (keep simple) */
    if(strchr(service, '\t') || strchr(user, '\t') || strchr(pass, '\t') ||
       strchr(service, '\n') || strchr(user, '\n') || strchr(pass, '\n')){
        fprintf(stderr, "Tabs/newlines not allowed in fields (Part 1 constraint)\n");
        fclose(f);
        return 1;
    }
    fprintf(f, "%s\t%s\t%s\n", service, user, pass);
    fclose(f);
    printf("Added entry for service: %s\n", service);
    return 0;
}

/* list: print only the service names */
static int cmd_list(void){
    FILE *f = fopen(VAULT_FILE, "r");
    if(!f) die("fopen");
    char line[MAX_LINE];
    while(fgets(line, sizeof line, f)){
        if(line[0] == '#') continue; /* skip header/comment */
        char *svc = strtok(line, "\t\n");
        if(!svc) continue;
        printf("%s\n", svc);
    }
    fclose(f);
    return 0;
}

/* show: find a service and print username+password */
static int cmd_show(const char *service){
    if(!service){
        fprintf(stderr, "Usage: vault show --service S\n");
        return 1;
    }
    FILE *f = fopen(VAULT_FILE, "r");
    if(!f) die("fopen");
    char line[MAX_LINE];
    int found = 0;
    while(fgets(line, sizeof line, f)){
        if(line[0] == '#') continue;
        /* copy because strtok mutates */
        char buf[MAX_LINE];
        strncpy(buf, line, sizeof buf);
        buf[sizeof buf - 1] = '\0';

        char *svc = strtok(buf, "\t\n");
        char *usr = strtok(NULL, "\t\n");
        char *pwd = strtok(NULL, "\t\n");
        if(!svc || !usr || !pwd) continue;

        if(strcmp(svc, service) == 0){
            printf("service : %s\nuser    : %s\npass    : %s\n", svc, usr, pwd);
            found = 1;
            break;
        }
    }
    fclose(f);
    if(!found){
        fprintf(stderr, "No entry found for service: %s\n", service);
        return 1;
    }
    return 0;
}

/* very tiny CLI parser for Part 1 */
int main(int argc, char **argv){
    if(argc < 2){
        fprintf(stderr,
            "Usage:\n"
            "  vault init\n"
            "  vault add --service S --user U --pass P\n"
            "  vault list\n"
            "  vault show --service S\n");
        return 1;
    }

    if(strcmp(argv[1], "init") == 0){
        return cmd_init();
    } else if(strcmp(argv[1], "add") == 0){
        const char *svc=NULL, *usr=NULL, *pwd=NULL;
        for(int i=2;i<argc;i++){
            if(strcmp(argv[i], "--service")==0 && i+1<argc) svc=argv[++i];
            else if(strcmp(argv[i], "--user")==0 && i+1<argc) usr=argv[++i];
            else if(strcmp(argv[i], "--pass")==0 && i+1<argc) pwd=argv[++i];
        }
        return cmd_add(svc, usr, pwd);
    } else if(strcmp(argv[1], "list") == 0){
        return cmd_list();
    } else if(strcmp(argv[1], "show") == 0){
        const char *svc=NULL;
        for(int i=2;i<argc;i++){
            if(strcmp(argv[i], "--service")==0 && i+1<argc) svc=argv[++i];
        }
        return cmd_show(svc);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }
}
