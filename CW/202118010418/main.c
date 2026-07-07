//
// Created by Yun on 25-5-12.
//

#include "common.h"

int main() {
    // 管理员密码管理
    FILE *kf = fopen(ADMIN_KEY_FILE, "rb");
    if (!kf) {
        char p[256];
        printf("Set admin password: ");
        scanf("%255s", p);
        set_password(p);
        printf("Password set!\n");
    } else {
        fclose(kf);
        char p[256];
        do {
            printf("Enter admin password: ");
            scanf("%255s", p);
        } while (!verify_password(p) && printf("Wrong, try again.\n"));
    }

    while (1) {
        printf("\n1) Encrypt  2) Decrypt  3) Exit\nChoice: ");
        int opt; if (scanf("%d", &opt)!=1) break;
        if (opt == 3) break;

        // 列出文件
        DIR *d = opendir(".");
        struct dirent *e;
        char *list[100]; int cnt=0;
        while ((e = readdir(d))) {
            if (e->d_type == DT_REG) {
                if (opt == 1 && !strstr(e->d_name, ".encrypted"))
                    list[cnt++] = strdup(e->d_name);
                else if (opt == 2 && strstr(e->d_name, ".encrypted"))
                    list[cnt++] = strdup(e->d_name);
            }
        }
        closedir(d);

        if (!cnt) { printf("No files found.\n"); continue; }
        printf("Files:\n");
        for (int i=0; i<cnt; i++) printf("%d. %s\n", i+1, list[i]);

        printf("Enter indices (space sep, end -1): ");
        int idx[100], n=0, x;
        while (scanf("%d", &x)==1 && x!=-1)
            if (x>=1 && x<=cnt) idx[n++]=x-1;
        getchar();

        char *sel[100];
        for (int i=0;i<n;i++) sel[i]=list[idx[i]];
        if (opt == 1) encrypt_process(sel, n);
        else          decrypt_process(sel, n);

        for (int i=0;i<cnt;i++) free(list[i]);
    }
    return 0;
}
