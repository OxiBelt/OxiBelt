#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Native, static, finite workload. No cgroup or host policy writes. */
static void fail(void) { fputs("{\"error\":\"probe-failed\"}\n", stdout); fflush(stdout); exit(111); }
static void read_value(const char *name, char *value, size_t size) {
  char path[128];
  if (snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", name) < 0) fail();
  FILE *file = fopen(path, "r");
  if (file == NULL || fgets(value, (int)size, file) == NULL) fail();
  if (strchr(value, '\n') == NULL || fgetc(file) != EOF) fail();
  fclose(file);
  value[strcspn(value, "\n")] = '\0';
}
static uint64_t number(const char *value) {
  char *end = NULL;
  errno = 0;
  if (*value < '0' || *value > '9') fail();
  uint64_t result = strtoull(value, &end, 10);
  if (errno || end == value || *end) fail();
  return result;
}
static uint64_t counter(const char *name, const char *key) {
  char path[128], line[256], actual[128];
  unsigned long long value;
  if (snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", name) < 0) fail();
  FILE *file = fopen(path, "r");
  if (!file) fail();
  for (unsigned count = 0; count < 64 && fgets(line, sizeof(line), file); ++count) {
    if (sscanf(line, "%127s %llu", actual, &value) == 2 && strcmp(actual, key) == 0) {
      fclose(file);
      return (uint64_t)value;
    }
  }
  fclose(file);
  fail();
  return 0;
}
static double seconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value)) fail();
  return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}
static void cpu(void) {
  uint64_t before = counter("cpu.stat", "nr_throttled");
  double end = seconds() + 2.0;
  volatile uint64_t work = 1;
  while (seconds() < end) {
    for (unsigned i = 0; i < 100000; ++i) work = work * 1664525 + 1013904223;
  }
  uint64_t after = counter("cpu.stat", "nr_throttled");
  printf("{\"mode\":\"cpu\",\"nr_throttled_before\":%" PRIu64 ",\"nr_throttled_after\":%" PRIu64 "}\n", before, after);
  if (after <= before) fail();
}
static void memory(void) {
  size_t bytes = 96U * 1024U * 1024U;
  volatile unsigned char *allocation = malloc(bytes);
  if (!allocation) fail();
  for (size_t i = 0; i < bytes; i += 4096) allocation[i] = 42;
  /* Successful allocation is a failed positive control, never a pass. */
  free((void *)allocation);
  fail();
}
static void pids(void) {
  uint64_t before = counter("pids.events", "max");
  int descriptors[2];
  if (pipe(descriptors)) fail();
  pid_t children[40];
  unsigned count = 0;
  int blocked = 0;
  for (; count < 40; ++count) {
    pid_t child = fork();
    if (child < 0) { blocked = errno == EAGAIN; break; }
    if (child == 0) {
      close(descriptors[1]);
      char buffer;
      while (read(descriptors[0], &buffer, 1) < 0 && errno == EINTR) {}
      close(descriptors[0]);
      _exit(0);
    }
    children[count] = child;
  }
  uint64_t after = counter("pids.events", "max");
  close(descriptors[1]);
  close(descriptors[0]);
  int cleanup = 1;
  for (unsigned i = 0; i < count; ++i) {
    int status;
    pid_t waited;
    do { waited = waitpid(children[i], &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != children[i] || !WIFEXITED(status) || WEXITSTATUS(status) != 0) cleanup = 0;
  }
  printf("{\"mode\":\"pids\",\"children\":%u,\"fork_blocked\":%s,\"pids_max_before\":%" PRIu64 ",\"pids_max_after\":%" PRIu64 ",\"children_reaped\":%s}\n",
      count, blocked ? "true" : "false", before, after, cleanup ? "true" : "false");
  if (!blocked || count == 0 || count > 31 || after <= before || !cleanup) fail();
}
int main(int argc, char **argv) {
  if (argc != 2) fail();
  struct utsname identity;
  if (uname(&identity) || strcmp(identity.sysname, "Linux") || strcmp(identity.machine, "riscv64")) fail();
  unsigned char elf[20];
  FILE *file = fopen("/proc/self/exe", "rb");
  if (!file || fread(elf, 1, sizeof(elf), file) != sizeof(elf)) fail();
  fclose(file);
  if (memcmp(elf, "\177ELF\002\001", 6) || elf[18] != 243 || elf[19] != 0 || getuid() == 0 || geteuid() == 0) fail();
  char membership[256];
  file = fopen("/proc/self/cgroup", "r");
  if (!file || !fgets(membership, sizeof(membership), file) || strcmp(membership, "0::/\n") || fgetc(file) != EOF) fail();
  fclose(file);
  char cpu_max[128], memory_max[128], swap_max[128], pids_max[128];
  read_value("cpu.max", cpu_max, sizeof(cpu_max));
  read_value("memory.max", memory_max, sizeof(memory_max));
  read_value("memory.swap.max", swap_max, sizeof(swap_max));
  read_value("pids.max", pids_max, sizeof(pids_max));
  if (strcmp(cpu_max, "50000 100000") || number(memory_max) != 67108864 || number(swap_max) != 0 || number(pids_max) != 32) fail();
  printf("{\"schema_version\":1,\"architecture\":\"riscv64\",\"executable_machine\":\"riscv64\",\"nonroot\":true,\"membership\":\"0::/\",\"cpu_max\":\"50000 100000\",\"memory_max\":67108864,\"memory_swap_max\":0,\"pids_max\":32}\n");
  fflush(stdout);
  if (!strcmp(argv[1], "cpu")) cpu();
  else if (!strcmp(argv[1], "memory")) memory();
  else if (!strcmp(argv[1], "pids")) pids();
  else fail();
  fflush(stdout);
  return 0;
}
