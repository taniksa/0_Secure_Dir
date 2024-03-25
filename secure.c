#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_PASSWORD_LENGTH 50
#define DIRECTORY_NAME "secure_directory"

int is_correct_password(const char *password) {
    const char *correct_password = "MySecurePassword123"; // Change this to your desired correct password
    return strcmp(password, correct_password) == 0;
}

void access_granted() {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Access granted! You can now access the secure directory.\n");
        char directory_path[1024];
        snprintf(directory_path, sizeof(directory_path), "%s/%s", cwd, DIRECTORY_NAME);
        if (access(directory_path, F_OK) == -1) {
            // Directory does not exist, create it
            if (mkdir(directory_path, 0700) == -1) {
                perror("mkdir");
                exit(EXIT_FAILURE);
            }
            printf("Secure directory created at: %s\n", directory_path);
        } else {
            printf("Secure directory already exists at: %s\n", directory_path);
        }
    } else {
        perror("getcwd");
        exit(EXIT_FAILURE);
    }
}

void access_denied() {
    printf("Access denied! Incorrect password.\n");
}

int main() {
    char password[MAX_PASSWORD_LENGTH];

    printf("Enter the password: ");
    fgets(password, MAX_PASSWORD_LENGTH, stdin);
    password[strcspn(password, "\n")] = 0; // Remove trailing newline character

    if (is_correct_password(password)) {
        access_granted();
    } else {
        access_denied();
    }

    return 0;
}
