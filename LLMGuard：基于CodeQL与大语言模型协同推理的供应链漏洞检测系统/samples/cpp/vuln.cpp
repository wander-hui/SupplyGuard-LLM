#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>

// CWE-120: strcpy 无边界检查, 外部输入溢出
void copy_input(const char *src) {
    char buf[64];
    strcpy(buf, src);            // sink: strcpy
    printf("%s\n", buf);
}

// CWE-78: system 执行外部输入
void run_command() {
    char cmd[256];
    scanf("%s", cmd);            // source: scanf
    system(cmd);                 // sink: system
}

// CWE-94: dlopen 动态加载外部路径
void load_lib(const char *path) {
    void *h = dlopen(path, RTLD_NOW);   // sink: dlopen
    (void)h;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        copy_input(argv[1]);     // source: argv
        load_lib(argv[1]);
    }
    run_command();
    return 0;
}
