
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>     /* inet_ntop */
#include <netinet/in.h>    /* sockaddr_in / sockaddr_in6 */
#include <sys/un.h>        /* sockaddr_un */
#include <unistd.h>        /* readlink */

typedef int64_t (*syscall_hook_fn_t)(int64_t,int64_t,int64_t,int64_t,
                                     int64_t,int64_t,int64_t);

static syscall_hook_fn_t real_syscall = NULL;   /* trigger_syscall() */

/* ────────────────────────────────────────────────────────── helpers ── */


static void log_openat_fmt(int dirfd,const char *path,long flags,long mode,long rv)
{
    if(dirfd == -100)
        fprintf(stderr,
            "[logger] openat(AT_FDCWD, \"%s\", 0x%lx, %#o) = %ld\n",
            path, flags, (unsigned)mode, rv);
    else
        fprintf(stderr,
            "[logger] openat(%d, \"%s\", 0x%lx, %#o) = %ld\n",
            dirfd, path, flags, (unsigned)mode, rv);
}

static void escape(const void *src,size_t n,char *dst,size_t *out)
{
    const unsigned char *s = src;
    size_t k = 0;
    for(size_t i=0;i<n && k<128;i++){
        unsigned c=s[i];
        if(c=='\n'){ dst[k++]='\\'; dst[k++]='n'; }
        else if(c=='\r'){ dst[k++]='\\'; dst[k++]='r'; }
        else if(c=='\t'){ dst[k++]='\\'; dst[k++]='t'; }
        else if(c>31 && c<127){ dst[k++]=c; }
        else { k+=sprintf(dst+k,"\\x%02x",c); }
    }
    dst[k]='\0';
    *out=k;
}

static void log_rw(const char *tag,int fd,const void *buf,size_t cnt,long rv)
{
    char tmp[256];                       /* plenty for 32 bytes → escaped */
    size_t shown = 0;

    size_t slice = (rv > 32) ? 32 : (rv > 0 ? (size_t)rv : 0);

    escape(buf, slice, tmp, &shown);     

    const char *ellipsis = (rv > 32) ? "..." : "";

    fprintf(stderr,
        "[logger] %s(%d, \"%s\"%s, %zu) = %ld\n",
        tag, fd, tmp, ellipsis, cnt, rv);
}

static void log_connect(int fd,const struct sockaddr *sa,socklen_t len,long rv)
{
    char addr[INET6_ADDRSTRLEN+8]={0};

    if(sa->sa_family==AF_INET){
        const struct sockaddr_in *v4=(const struct sockaddr_in*)sa;
        snprintf(addr,sizeof addr,"%s:%u",
                 inet_ntoa(v4->sin_addr), ntohs(v4->sin_port));
    }else if(sa->sa_family==AF_INET6){
        const struct sockaddr_in6 *v6=(const struct sockaddr_in6*)sa;
        inet_ntop(AF_INET6,&v6->sin6_addr,addr,sizeof addr);
        size_t l=strlen(addr);
        snprintf(addr+l,sizeof addr-l,":%u",ntohs(v6->sin6_port));
    }else if(sa->sa_family==AF_UNIX){
        const struct sockaddr_un *ux=(const struct sockaddr_un*)sa;
        snprintf(addr,sizeof addr,"UNIX:%s",ux->sun_path[0] ? ux->sun_path : "(null)");
    }else{
        snprintf(addr,sizeof addr,"AF_%d",sa->sa_family);
    }

    fprintf(stderr,
        "[logger] connect(%d, \"%s\", %u) = %ld\n",
        fd, addr, len, rv);
}

static void log_execve(const char *path,const void *argv,const void *envp)
{
    fprintf(stderr,
        "[logger] execve(\"%s\", %p, %p)\n",
        path, argv, envp);
}

/* ───────────────────────────────────────────────────────── hook ───── */

static int64_t hook(int64_t rdi,int64_t rsi,int64_t rdx,
                    int64_t r10,int64_t r8 ,int64_t r9 ,
                    int64_t rax)
{
    if(rax==59){
        printf("check\n");
        log_execve((char*)rdi,(void*)rsi,(void*)rdx);
    }
    long rv = real_syscall(rdi,rsi,rdx,r10,r8,r9,rax);
    //printf("%ld\n",rax);
    switch(rax){
        case 257: /* openat */
            log_openat_fmt((int)rdi,(char*)rsi,rdx,r10,rv);
            break;
        case 0:   /* read */
            log_rw("read",(int)rdi,(void*)rsi,(size_t)rdx,rv);
            break;
        case 1:   /* write */
            log_rw("write",(int)rdi,(void*)rsi,(size_t)rdx,rv);
            break;
        case 42:  /* connect */
            log_connect((int)rdi,(struct sockaddr*)rsi,(socklen_t)rdx,rv);
            break;

        default:
            break;
    }
    return rv;
}

/* ─────────────────────────────────────────── required entry point ── */

void __hook_init(const syscall_hook_fn_t trigger,
                 syscall_hook_fn_t *target_ptr)
{
    real_syscall  = trigger;      /* keep raw kernel entry */
    *target_ptr   = hook;         /* let zpoline call our hook */
}
