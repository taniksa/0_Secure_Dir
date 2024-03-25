#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_PASSWORD_LENGTH 50
#define DIRECTORY_NAME "secure_directory"
#define PASSWORD_FILE "password.txt"

// Function to read the stored password from the file
void read_password(char *password) {
    FILE *file = fopen(PASSWORD_FILE, "r");
    if (file != NULL) {
        fgets(password, MAX_PASSWORD_LENGTH, file);
        password[strcspn(password, "\n")] = 0; // Remove trailing newline character
        fclose(file);
    }
}

// Function to write the provided password to the file
void write_password(const char *password) {
    FILE *file = fopen(PASSWORD_FILE, "w");
    if (file != NULL) {
        fputs(password, file);
        fclose(file);
    } else {
        perror("Error writing password");
        exit(EXIT_FAILURE);
    }
}

int is_correct_password(const char *input_password) {
    char stored_password[MAX_PASSWORD_LENGTH];
    read_password(stored_password);
    return strcmp(input_password, stored_password) == 0;
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
    char stored_password[MAX_PASSWORD_LENGTH];

    // Check if there is already a stored password
    FILE *file = fopen(PASSWORD_FILE, "r");
    if (file != NULL) {
        // Password exists, ask for it
        printf("Enter the password: ");
        fgets(password, MAX_PASSWORD_LENGTH, stdin);
        password[strcspn(password, "\n")] = 0; // Remove trailing newline character

        if (is_correct_password(password)) {
            access_granted();
        } else {
            access_denied();
        }
        fclose(file);
    } else {
        // No stored password, set a new one
        printf("No password set. Please set a password: ");
        fgets(password, MAX_PASSWORD_LENGTH, stdin);
        password[strcspn(password, "\n")] = 0; // Remove trailing newline character
        write_password(password);
        printf("Password set successfully!\n");
    }

    return 0;
}
