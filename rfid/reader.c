#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/cdev.h>

#include "reader.h"

uint8_t searched_epc[EPC_MAX_LEN];
size_t searched_epc_len = 0;

uint16_t crc_checksum(uint8_t *data, int len) {
  // crc16_mcrf4xx algorithm
  uint16_t crc = INITIAL_CRC;

  if (!data || len < 0)
    return crc;

  while (len--) {
    crc ^= *data++;
    for (int i = 0; i < 8; i++) {
      if (crc & 0x0001)
        crc = (crc >> 1) ^ CRC_POLYNOMIAL;
      else
        crc = (crc >> 1);
    }
  }
  return crc;
}

int write_frame(struct file *serial_file, reader_command_t *cmd) {
  uint8_t HEADER_SIZE = 4;
  uint16_t crc;
  ssize_t num_bytes_written;
  size_t len = cmd->size + HEADER_SIZE;
  size_t off = 0;
  uint8_t *buff = kmalloc(sizeof(uint8_t) * (len+1), GFP_KERNEL);

  SHOW_READER_COMMAND(cmd);

  buff[off++] = len;
  buff[off++] = cmd->addr;
  buff[off++] = cmd->cmd;

  memcpy(&buff[off], cmd->data, cmd->size);

  off += cmd->size;

  crc = crc_checksum(buff, len - 1);

  buff[off++] = CRC_LSB(crc);
  buff[off++] = CRC_MSB(crc);

  num_bytes_written = kernel_write(serial_file, buff, len+1, &serial_file->f_pos);

  if (num_bytes_written < 0) {
      return num_bytes_written;
  }
  kfree(buff);
  return num_bytes_written;
}


ssize_t read_frame(struct file *serial_file, uint8_t *buffer) {
  int length = 0;
  ssize_t num_bytes_read = 0;
  int i = 0;
  int MAX_ITER = 1000 * 1000;

  LOG("Reading from device");

  while (num_bytes_read <= 0 && i < MAX_ITER) {
      num_bytes_read = kernel_read(serial_file, &length, sizeof(uint8_t), &serial_file->f_pos);
      i += 1;
  }
  if (num_bytes_read < 0) {
      return num_bytes_read;
  }
  if (DEBUG_LOG_ENABLED) LOG("[%d] Received %zd bytes of length", i, num_bytes_read);

  num_bytes_read = kernel_read(serial_file, buffer+1, length, &serial_file->f_pos);
  if (num_bytes_read == -1) {
      return num_bytes_read;
  }
  buffer[0] = (uint8_t) num_bytes_read;

  if (DEBUG_LOG_ENABLED) SHOW_BUFFER("Received", (buffer+1), num_bytes_read);
  return num_bytes_read + 1;
}

int verify_checksum(uint8_t *data, ssize_t data_len, uint8_t *checksum_bytes) {
  uint16_t crc = crc_checksum(data, data_len);
  return (
      (checksum_bytes[0] == CRC_LSB(crc)) &&
      (checksum_bytes[1] == CRC_MSB(crc))
  );
}

int parse_frame(uint8_t *buffer, ssize_t buffer_size, reader_response_t *frame) {
  uint8_t HEADER_SIZE = 4;
  uint8_t CHECKSUM_SIZE = 2;
  int off = 1;

  if (buffer_size < HEADER_SIZE + CHECKSUM_SIZE) {
    printk(
        KERN_NOTICE "Response must be at least %d bytes\n",
        HEADER_SIZE + CHECKSUM_SIZE
    );
    return -1;
  }

  frame->size = buffer_size - HEADER_SIZE - CHECKSUM_SIZE;
  frame->reader_addr = buffer[off++];
  frame->resp_cmd = buffer[off++];
  frame->status = buffer[off++];
  frame->data = kmalloc(sizeof(uint8_t) * frame->size, GFP_KERNEL);

  for (uint8_t i = 0; i < frame->size; i++) {
      frame->data[i] = buffer[off++];
  }

  if (verify_checksum(
        buffer,
        buffer_size - CHECKSUM_SIZE,
        &buffer[off]
      ) != 1) {

    printk(KERN_NOTICE "Error verifying checksum\n");
    return -1;
  }
  return 0;
}

void free_frame(reader_response_t *frame) {
  kfree(frame->data);
}

int run_command(
    struct file *serial_file,
    reader_command_t *cmd,
    reader_response_t *reader_resp
) {
  ssize_t num_bytes_read;
  uint8_t buffer[CMD_RESPONSE_BUFFER_SIZE] = {0};

  if (write_frame(serial_file, cmd) < 0) {
      return -1;
  }
  num_bytes_read = read_frame(serial_file, buffer);
  if (num_bytes_read < 0) {
      return -1;
  }
  if (parse_frame(buffer, num_bytes_read, reader_resp) < 0) {
      free_frame(reader_resp);
      return -1;
  }
  SHOW_READER_RESPONSE(reader_resp);
  return 0;
}

int translate_antenna_num(int antenna_code) {
    if (antenna_code == 1) return 1;
    if (antenna_code == 2) return 2;
    if (antenna_code == 4) return 3;
    if (antenna_code == 8) return 4;
    return -1;
}

int parse_inventory_data(
  reader_response_t *resp,
  inventory_data_t *inventory
) {
  int off = 0;
  int antenna_num = translate_antenna_num(resp->data[off++]);
  if (antenna_num == -1) {
    printk(KERN_NOTICE "Invalid antenna number\n");
    return -1;
  }

  inventory->antenna = (uint8_t) antenna_num;
  inventory->num_tags = resp->data[off++];

  // XXX: Okey so these allocations here are intentionally kinda off and I would like to
  // hear opinions from reviewers on what is the best way to do it.
  //
  // Context: We query the reader, it returns bytes, we want to parse it into
  // inventory_data_t structure
  //
  // Where should this logic live?
  // 1. In kernel driver.
  //  I probably can't do such dynamic allocation like done here in a loop, but instead
  //  should calculate requried # of bytes and mmap a continous memory to put all of the
  //  tags there, so that I could return one pointer to the userspace. Yet then, userspace
  //  code will need to do parsing once again, due to dynamic nature of response frames
  //  length
  //
  // 2. In userspace.
  //  It simplifies the driver code, as the reader already returns continous memory will
  //  all the data! that lives under resp->data, so maybe the best way would be to return
  //  it to the user, and let him handle the parsing into `inventory_data_t`.
  //
  // 2'. Can I somehow expose to the userspace a function doing the parsing?
  //
  // TODO: consider using devm_kzalloc instead
  inventory->tags = kmalloc(sizeof(inventory_tag_t*) * inventory->num_tags, GFP_KERNEL);

  for (int i = 0; i < inventory->num_tags; i++) {
    inventory_tag_t *tag = kmalloc(sizeof(inventory_tag_t), GFP_KERNEL);
    inventory->tags[i] = tag;

    tag->epc_len = resp->data[off++];

    for (int i = 0; i < tag->epc_len; i++) {
      tag->epc[i] = resp->data[off++];
    }
    tag->rssi = resp->data[off++];
  }

  SHOW_INVENTORY_DATA(inventory);

  return 0;
}

void free_inventory_data(inventory_data_t *inventory) {
  for (int i = 0; i < inventory->num_tags; i++) {
    kfree(inventory->tags[i]);
  }
  kfree(inventory->tags);
}

int read_tags(struct file *serial_file) {
  // Query inventory for the nearest avaiable RFID tags

  reader_response_t reader_resp;
  inventory_data_t inventory;
  uint8_t data[] = {
    0x04,   // q_value
    0x00,   // session
    0x01,   // mask source
    0x00,   // mask addr 1
    0x00,   // mask addr 2
    0x00,   // masklen
    0x00,   // target
    0x80,   // antenna
    0x14,   // scan time
  };

  reader_command_t inventory_cmd = {
    .addr = 0xFF,
    .cmd = CMD_TAG_INVENTORY,
    .size = sizeof(data),
    .data = data,
  };
  LOG("Reading RFID tags");

  if (run_command(serial_file, &inventory_cmd, &reader_resp) != 0) {
    return -1;
  }

  if (parse_inventory_data(&reader_resp, &inventory) < 0) {
    free_inventory_data(&inventory);
    return -1;
  }

  free_frame(&reader_resp);
  free_inventory_data(&inventory);
  return 0;
}

int set_buzzer(struct file *serial_file, uint8_t value) {
  // Pass value = 1 to enable buzzer, 0 to disable

  int ret;
  reader_response_t reader_resp;
  reader_command_t cmd = {
    .addr = 0xFF,
    .cmd = CF_SET_BUZZER_ENABLED,
    .size = 1,
    .data = (uint8_t[]) { value },
  };

  ret = run_command(serial_file, &cmd, &reader_resp);
  if (!ret)
    free_frame(&reader_resp);
  return ret;
}

int set_power(struct file *serial_file, uint8_t value) {
  // Integer value in range [0 - 30]

  int ret;
  reader_response_t reader_resp;
  reader_command_t cmd = {
    .addr = 0xFF,
    .cmd = CF_SET_RF_POWER,
    .size = 1,
    .data = (uint8_t[]) { value },
  };

  if (value > MAX_POWER) {
    printk(KERN_NOTICE "Power must be in range 0-%d, was: %d\n", MAX_POWER, value);
    return -1;
  }
  ret = run_command(serial_file, &cmd, &reader_resp);
  if (!ret)
    free_frame(&reader_resp);
  return ret;
}

int set_scan_time(struct file *serial_file, uint8_t value) {
  // Integer value in range [3 - 255]

  int ret;
  reader_response_t reader_resp;
  reader_command_t cmd = {
    .addr = 0xFF,
    .cmd = CF_SET_READER_INVENTORY_TIME,
    .size = 1,
    .data = (uint8_t[]) { value },
  };

  if (value < MIN_SCAN_TIME) {
    printk(KERN_NOTICE
        "Scan time must be in range %d-%d, was: %d\n",
        MIN_SCAN_TIME, MAX_SCAN_TIME, value
    );
    return -1;
  }

  ret = run_command(serial_file, &cmd, &reader_resp);
  if (!ret)
    free_frame(&reader_resp);
  return ret;
}

MODULE_DESCRIPTION("RFID tags reader");
MODULE_AUTHOR("Mateusz Urbańczyk <urbanczyk@google.com>");
MODULE_LICENSE("GPL");
