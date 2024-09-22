#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// Function to check if a string contains only digits
int is_number(const char *str) {
  while (*str) {
    if (!isdigit(*str))
      return 0;
    str++;
  }
  return 1;
}

// Function to get the process ID from its name
pid_t find_process(const char *process_name) {
  DIR *dir;
  struct dirent *entry;

  // Open the /proc directory
  if (!(dir = opendir("/proc"))) {
    perror("opendir");
    return -1;
  }

  // Loop through all entries in the /proc directory
  while ((entry = readdir(dir)) != NULL) {
    // Check if the entry is a directory and its name is a number (PID)
    if (entry->d_type == DT_DIR && is_number(entry->d_name)) {
      char cmdline_path[256];
      char cmdline[256];
      FILE *cmdline_file;

      // Construct the path to the cmdline file
      snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline",
               entry->d_name);

      // Open the cmdline file
      cmdline_file = fopen(cmdline_path, "r");
      if (cmdline_file) {
        // Read the command line
        fgets(cmdline, sizeof(cmdline), cmdline_file);
        fclose(cmdline_file);

        // Check if the command line contains the process name
        if (strstr(cmdline, process_name)) {
          closedir(dir);
          return atoi(entry->d_name); // Return the PID
        }
      }
    }
  }

  closedir(dir);
  return -1; // Return -1 if process not found
}

typedef struct mapping mapping_t;
struct mapping {
  unsigned long start;
  unsigned long end;
  unsigned long offset;
  char *permissions;
  unsigned long inode;
  char *pathname;

  // Linked list
  mapping_t *next;
};

unsigned long get_mapping_size(mapping_t *mapping) {
  return mapping->end - mapping->start;
}

size_t get_num_mappings(mapping_t *head) {
  size_t count = 0;
  mapping_t *current = head;
  while (current != NULL) {
    count++;
    current = current->next;
  }
  return count;
}

void print_mapping(mapping_t *mapping) {
  if (mapping == NULL) {
    printf("Mapping is NULL\n");
    return;
  }
  printf("Start: %lx\n", mapping->start);
  printf("End: %lx\n", mapping->end);
  printf("Size: %lx\n", get_mapping_size(mapping));
  printf("Offset: %lx\n", mapping->offset);
  printf("Permissions: %s\n", mapping->permissions);
  printf("Inode: %lu\n", mapping->inode);
  printf("Pathname: %s\n", mapping->pathname ? mapping->pathname : "N/A");
  printf("\n");
}

// Function to create a new mapping node
mapping_t *create_mapping_node(unsigned long start, unsigned long end,
                               unsigned long offset, char *permissions,
                               unsigned long inode, char *pathname) {
  mapping_t *node = (mapping_t *)malloc(sizeof(mapping_t));
  if (node == NULL) {
    perror("malloc");
    return NULL;
  }

  node->start = start;
  node->end = end;
  node->offset = offset;
  node->permissions = strdup(permissions); // Duplicate permissions string
  node->inode = inode;
  node->pathname =
      pathname ? strdup(pathname) : NULL; // Duplicate pathname if available
  node->next = NULL;

  return node;
}

// Function to free the memory of the linked list
void free_mappings(mapping_t *head) {
  mapping_t *temp;
  while (head != NULL) {
    temp = head;
    head = head->next;
    free(temp->permissions);
    free(temp->pathname);
    free(temp);
  }
}

// Function to read the /proc/[pid]/maps and return a linked list of memory
// mappings
mapping_t *read_maps(pid_t pid) {
  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps",
           pid); // Construct the path to /proc/[pid]/maps

  FILE *file = fopen(maps_path, "r");
  if (file == NULL) {
    perror("fopen");
    return NULL;
  }

  mapping_t *head = NULL;
  mapping_t *current = NULL;

  char line[256];
  while (fgets(line, sizeof(line), file)) {
    unsigned long start, end, offset, inode;
    char permissions[5]; // Permissions are of the form rwxp, which is at most 4
                         // characters + null terminator
    char pathname[256] = ""; // File path if available

    // Parse each line in the format:
    // start-end perms offset dev inode pathname (optional)
    // Example: 00400000-00452000 r-xp 00000000 08:01 123456 /bin/bash
    int parsed = sscanf(line, "%lx-%lx %4s %lx %*s %lu %s", &start, &end,
                        permissions, &offset, &inode, pathname);

    // Create a new mapping node and append it to the linked list
    mapping_t *node = create_mapping_node(start, end, offset, permissions,
                                          inode, parsed == 6 ? pathname : NULL);

    if (node == NULL) {
      free_mappings(head);
      fclose(file);
      return NULL;
    }

    if (head == NULL) {
      head = node;
      current = node;
    } else {
      current->next = node;
      current = node;
    }
  }

  fclose(file);
  return head;
}

unsigned long get_dex_size(unsigned char *buffer, unsigned long i) {
  // Read a uint at buffer[i + 0x20]
  unsigned int size = *(unsigned int *)(buffer + i + 0x20);
  return size;
}

bool verify_dex(unsigned long addr, mapping_t *mapping, unsigned char *buffer,
                unsigned long i) {
  unsigned long mapping_end = mapping->end;

  if (addr + 0x70 > mapping_end) {
    return false;
  }

  if (addr + get_dex_size(buffer, i) > mapping_end) {
    return false;
  }

  // Read addr + 0x3c. This should equal to 0x70
  if (buffer[i + 0x3c] != 0x70) {
    return false;
  }

  return true;
}

char DEX_MAGIC[] = {0x64, 0x65, 0x78, 0x0a, 0x30};

typedef struct dex dex_t;
struct dex {
  unsigned char *buffer;
  unsigned long addr;
  unsigned int size;
  mapping_t *mapping;
};

dex_t *scan_mem(pid_t pid, mapping_t *region) {
  unsigned long start = region->start;
  unsigned long end = region->start + (1 << 20);

  // Read /proc/[pid]/mem, seek to the start of the region, and read the memory
  // contents

  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd == -1) {
    perror("open");
    return NULL;
  }

  if (lseek(mem_fd, start, SEEK_SET) == -1) {
    perror("lseek");
    close(mem_fd);
    return NULL;
  }

  unsigned char *buffer = (unsigned char *)malloc(end - start);

  ssize_t bytes_read = read(mem_fd, buffer, end - start);
  if (bytes_read == -1) {
    perror("read");
  }

  close(mem_fd);

  // Scan
  for (unsigned long i = 0; i < end - start - sizeof(DEX_MAGIC); i++) {
    if (memcmp(buffer + i, DEX_MAGIC, sizeof(DEX_MAGIC)) == 0) {

      if (verify_dex(start + i, region, buffer, i)) {

        unsigned int size = get_dex_size(buffer, i);
        printf("DEX Size: %u MB = %u KB\n", size / (1 << 20), size / 1024);

        dex_t *dex = (dex_t *)malloc(sizeof(dex_t));
        dex->buffer = buffer + i;
        dex->addr = start + i;
        dex->size = size;

        return dex;
      }
    }
  }

  return 0;
}

void dump_mem(pid_t pid, unsigned long start, unsigned long end) {

  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

  char dump_path[64];
  snprintf(dump_path, sizeof(dump_path), "./dump_%lx-%lx.dex", start, end);

  printf("Dumping memory region %lx-%lx to %s...\n", start, end, dump_path);

  int mem_fd = open(mem_path, O_RDONLY);
  if (mem_fd == -1) {
    perror("open");
    return;
  }

  int dump_fd = open(dump_path, O_CREAT | O_WRONLY, 0644);
  if (dump_fd == -1) {
    perror("open");
    return;
  }

  if (lseek(mem_fd, start, SEEK_SET) == -1) {
    perror("lseek");
    close(mem_fd);
    return;
  }

  char buffer[4096];
  ssize_t bytes_read;
  while (start < end) {
    bytes_read = read(mem_fd, buffer, sizeof(buffer));
    if (bytes_read == -1) {
      perror("read");
      break;
    }
    if (write(dump_fd, buffer, bytes_read) == -1) {
      perror("write");
      break;
    }
    start += bytes_read;
  }

  close(mem_fd);
  close(dump_fd);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <process name>\n", argv[0]);
    return 1;
  }
  pid_t pid = find_process(argv[1]);
  if (pid == -1) {
    printf("Process not found\n");
  } else {
    printf("Process ID: %d\n", pid);
  }

  mapping_t *mapping = read_maps(pid);

  if (mapping == NULL) {
    return 1;
  }

  printf("Number of memory mappings: %zu\n", get_num_mappings(mapping));

  // Scan
  mapping_t *current = mapping;
  while (current != NULL) {
    // Check if permission is "r--"
    // if (strcmp(current->permissions, "r--p"))
    //   goto end;
    // if (strstr(current->permissions, "r--") == NULL)
    //   goto end;

    if (current->pathname) {
      if (strstr(current->pathname, "/system/"))
        goto end;

      if (strstr(current->pathname, "/apex/"))
        goto end;

      if (strstr(current->pathname, "/dev/"))
        goto end;

      if (strstr(current->pathname, "/vendor/"))
        goto end;

      if (strstr(current->pathname, "/product/"))
        goto end;
    }

    // printf("Scanning region %lx-%lx (%s)...\n", current->start, current->end,
    //       current->pathname);
    dex_t *dex = scan_mem(pid, current);

    if (dex) {
      printf("Found DEX magic at %lx = %lx + %lx\n", dex->addr, current->start,
             dex->addr - current->start);

      print_mapping(current);
      dump_mem(pid, dex->addr, current->end);
    }

  end:
    current = current->next;
  }

  return 0;
}
