#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>

/* SupplyGuard-LLM 演示用 C/C++ 漏洞样本 (可被 make 编译)。
 * 外部输入来自 argv、scanf、getenv。 */

/* CWE-120: strcpy 无边界检查, 外部输入溢出栈缓冲区。 */
void copy_input(const char *src) {
    char buf[64];
    strcpy(buf, src);                 /* sink: strcpy */
    printf("%s\n", buf);
}

/* CWE-78: system 执行来自 scanf 的外部输入。 */
void run_command() {
    char cmd[256];
    if (scanf("%255s", cmd) == 1) {   /* source: scanf */
        system(cmd);                  /* sink: system */
    }
}

/* CWE-94: dlopen 加载来自环境变量的路径。 */
void load_plugin() {
    const char *path = getenv("PLUGIN_PATH");  /* source: getenv */
    if (path) {
        void *h = dlopen(path, RTLD_NOW);       /* sink: dlopen */
        (void)h;
    }
}

/* CWE-78: popen 执行 argv 输入。 */
void run_pipe(const char *arg) {
    char buf[256];
    snprintf(buf, sizeof(buf), "echo %s", arg);
    FILE *fp = popen(buf, "r");       /* sink: popen */
    if (fp) pclose(fp);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        copy_input(argv[1]);          /* source: argv */
        run_pipe(argv[1]);
    }
    run_command();
    load_plugin();
    return 0;
}
