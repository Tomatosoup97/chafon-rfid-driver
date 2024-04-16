#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

#define DEVICE_FILE "/dev/rfid-reader"
#define SERIAL_FILE "/dev/ttyUSB0"

// Control flow
#define SET_BUZZER 0
#define SET_POWER 0
#define SET_SCAN_TIME 0
#define BUZZER_ENABLED 0

// Constraints
#define MAX_POWER 30
#define MAX_SCAN_TIME 0xFF
#define MIN_SCAN_TIME 0x03

typedef enum {
  IOCTL_SET_FILE = _IO('d', 0x01),
  IOCTL_SET_SCAN_TIME = _IO('d', 0x02),
  IOCTL_SET_POWER = _IO('d', 0x03),
  IOCTL_SET_BUZZER = _IO('d', 0x04)
} IoctlCmd;

int issue_ioctl_command(int device_fd, IoctlCmd cmd, int *arg) {
  int rc = ioctl(device_fd, cmd, arg);

  if (rc < 0) {
    perror("ioctl");
    exit(EXIT_FAILURE);
  }

  printf("[ioctl] executed\n");
  return 0;
}

void device_read(int device_fd) {
  int bytes_read;
  const int BYTES_TO_READ = 5;
  char buffer[BYTES_TO_READ];

  bytes_read = read(device_fd, buffer, BYTES_TO_READ-1);
  printf("[rfid reader] bytes read: %d\n", bytes_read);

  if (bytes_read != BYTES_TO_READ-1) {
    perror("device fread failed");
    exit(EXIT_FAILURE);
  }

  buffer[BYTES_TO_READ-1] = '\0';

  printf("[rfid reader] read:\n%s\n", buffer);
}

void set_serial_config_flags(struct termios* serial_config) {
  // Set baud rate
  cfsetispeed(serial_config, B57600);
  cfsetospeed(serial_config, B57600);

  // Set data size, parity, and stop bits
  serial_config->c_cflag &= ~(PARENB | PARODD); // Disable parity
  serial_config->c_cflag &= ~CSTOPB; // Set one stop bit
  serial_config->c_cflag &= ~CSIZE;  // clear bit-size
  serial_config->c_cflag |= CS8; // Set data size to 8 bits

  serial_config->c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)

  serial_config->c_lflag &= ~ICANON; // disable canonical mode

  serial_config->c_lflag &= ~ECHO;   // Disable echo
  serial_config->c_lflag &= ~ECHOE;  // Disable erasure
  serial_config->c_lflag &= ~ECHONL; // Disable new-line echo
  serial_config->c_lflag &= ~ISIG;   // Disable interpretation of INTR, QUIT and SUSP
  serial_config->c_lflag &= ~IEXTEN;

  serial_config->c_iflag &= ~(IXON | IXOFF | IXANY); // Turn off s/w flow ctrl
  // Disable any special handling of received bytes:
  serial_config->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);
  serial_config->c_oflag &= ~OPOST; // Prevent special interpretation of output bytes (e.g. newline chars)
  serial_config->c_oflag &= ~ONLCR; // Prevent conversion of newline to carriage return/line feed
  serial_config->c_oflag &= ~OCRNL;

  // https://www.mkssoftware.com/docs/man5/struct_termios.5.asp
  // vmin "minimal number of characters to be read. 0 for non blocking"
  serial_config->c_cc[VTIME] = 255;
  serial_config->c_cc[VMIN] = 1;
}

int initialize_serial() {
  int serial_fd;
  const char *serial_port = SERIAL_FILE;

  // Open the serial port
  serial_fd = open(serial_port, O_RDWR | O_NOCTTY | O_NONBLOCK);
  if (serial_fd == -1) {
      perror("Error opening serial port");
      return -1;
  }

  // Set up the serial port configuration
  struct termios serial_config;
  if (tcgetattr(serial_fd, &serial_config) != 0) {
      perror("Error getting serial port attributes");
      close(serial_fd);
      return -1;
  }

  set_serial_config_flags(&serial_config);

  // Apply the new serial port configuration
  if (tcsetattr(serial_fd, TCSANOW, &serial_config) != 0) {
      perror("Error setting serial port attributes");
      close(serial_fd);
      return -1;
  }

  printf("Serial port setup complete\n");
  return serial_fd;
}


int main() {
    int serial_fd, device_fd, ioctl_value;

    device_fd = open(DEVICE_FILE, O_RDONLY);

    if (!device_fd) {
        perror("Failed to open device file");
        return 1;
    }

    serial_fd = initialize_serial();

    if (serial_fd < 0) {
        perror("Error opening serial device");
        return EXIT_FAILURE;
    }

    printf("Setting serial file to %d...\n", serial_fd);
    ioctl_value = serial_fd;
    issue_ioctl_command(device_fd, IOCTL_SET_FILE, &ioctl_value);

    if (SET_BUZZER) {
      printf("Setting buzzer...\n");
      ioctl_value = BUZZER_ENABLED;
      issue_ioctl_command(device_fd, IOCTL_SET_BUZZER, &ioctl_value);
    }

    if (SET_POWER) {
      printf("Setting power...\n");
      ioctl_value = MAX_POWER;
      issue_ioctl_command(device_fd, IOCTL_SET_POWER, &ioctl_value);
    }

    if (SET_SCAN_TIME) {
      printf("Setting scan time...\n");
      ioctl_value = MAX_SCAN_TIME;
      issue_ioctl_command(device_fd, IOCTL_SET_SCAN_TIME, &ioctl_value);
    }

    device_read(device_fd);

    close(device_fd);
    close(serial_fd);

    return 0;
}
