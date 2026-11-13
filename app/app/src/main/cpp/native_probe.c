#include <jni.h>

#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

JNIEXPORT jboolean JNICALL
Java_com_miyoubi_fracture_NativeProbe_isKernelSuActive(JNIEnv *env, jobject thiz) {
  (void)env;
  (void)thiz;

  if (access("/sys/module/kernelsu", F_OK) == 0) {
    return JNI_TRUE;
  }

  int fd = open("/proc/modules", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return JNI_FALSE;
  }

  char modules[65536];
  ssize_t count = read(fd, modules, sizeof(modules) - 1);
  close(fd);
  if (count <= 0) {
    return JNI_FALSE;
  }
  modules[count] = '\0';

  const char *line = modules;
  while (line != NULL && *line != '\0') {
    if (strncmp(line, "kernelsu ", sizeof("kernelsu ") - 1) == 0) {
      return JNI_TRUE;
    }
    line = strchr(line, '\n');
    if (line != NULL) {
      ++line;
    }
  }
  return JNI_FALSE;
}
