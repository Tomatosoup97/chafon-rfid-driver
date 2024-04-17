// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/cdev.h>

#include "reader.h"

u8 searched_epc[EPC_MAX_LEN];
size_t searched_epc_len;

uint16_t crc_checksum(u8 *data, int len)
{
	// crc16_mcrf4xx algorithm
	u16 crc = INITIAL_CRC;

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

int write_frame(struct rfid_reader *reader,
		struct file *serial_file,
		struct reader_command *cmd)
{
	u8 HEADER_SIZE = 4;
	u16 crc;
	ssize_t num_bytes_written;
	size_t len = cmd->size + HEADER_SIZE;
	size_t off = 0;
	u8 *buff = kmalloc(sizeof(uint8_t) * (len + 1), GFP_KERNEL);

	SHOW_READER_COMMAND(reader->dev, cmd);

	buff[off++] = len;
	buff[off++] = cmd->addr;
	buff[off++] = cmd->cmd;

	memcpy(&buff[off], cmd->data, cmd->size);

	off += cmd->size;

	crc = crc_checksum(buff, len - 1);

	buff[off++] = CRC_LSB(crc);
	buff[off++] = CRC_MSB(crc);

	num_bytes_written = kernel_write(serial_file, buff, len + 1, &serial_file->f_pos);

	if (num_bytes_written < 0)
		return num_bytes_written;

	kfree(buff);
	return num_bytes_written;
}

ssize_t read_frame(struct file *serial_file, uint8_t *buffer)
{
	int length = 0;
	ssize_t num_bytes_read = 0;
	int i = 0;
	int MAX_ITER = 1000 * 1000;

	while (num_bytes_read <= 0 && i < MAX_ITER) {
		num_bytes_read = kernel_read(serial_file,
					     &length,
					     sizeof(uint8_t),
					     &serial_file->f_pos);
		i += 1;
	}

	if (num_bytes_read < 0)
		return num_bytes_read;

	num_bytes_read = kernel_read(serial_file, buffer + 1, length, &serial_file->f_pos);

	if (num_bytes_read == -1)
		return num_bytes_read;

	buffer[0] = (uint8_t)num_bytes_read;

	return num_bytes_read + 1;
}

int verify_checksum(u8 *data, ssize_t data_len, uint8_t *checksum_bytes)
{
	u16 crc = crc_checksum(data, data_len);

	return ((checksum_bytes[0] == CRC_LSB(crc)) &&
		(checksum_bytes[1] == CRC_MSB(crc)));
}

int parse_frame(struct rfid_reader *reader,
		u8 *buffer,
		ssize_t buffer_size,
		struct reader_response *frame)
{
	u8 HEADER_SIZE = 4;
	u8 CHECKSUM_SIZE = 2;
	int off = 1;

	if (buffer_size < HEADER_SIZE + CHECKSUM_SIZE) {
		dev_err(reader->dev, "Response must be at least %d bytes\n",
			HEADER_SIZE + CHECKSUM_SIZE);
		return -1;
	}

	frame->size = buffer_size - HEADER_SIZE - CHECKSUM_SIZE;
	frame->reader_addr = buffer[off++];
	frame->resp_cmd = buffer[off++];
	frame->status = buffer[off++];
	frame->data = kmalloc_array(frame->size, sizeof(uint8_t), GFP_KERNEL);

	for (u8 i = 0; i < frame->size; i++)
		frame->data[i] = buffer[off++];

	if (verify_checksum(buffer,
			    buffer_size - CHECKSUM_SIZE,
			    &buffer[off]
	) != 1) {
		dev_err(reader->dev, "Error verifying checksum\n");
		return -1;
	}
	return 0;
}

void free_frame(struct reader_response *frame)
{
	kfree(frame->data);
}

int run_command(struct rfid_reader *reader,
		struct file *serial_file,
		struct reader_command *cmd,
		struct reader_response *reader_resp)
{
	ssize_t num_bytes_read;
	u8 buffer[CMD_RESPONSE_BUFFER_SIZE] = {0};

	if (write_frame(reader, serial_file, cmd) < 0)
		return -1;

	num_bytes_read = read_frame(serial_file, buffer);

	if (num_bytes_read < 0)
		return -1;

	if (parse_frame(reader, buffer, num_bytes_read, reader_resp) < 0) {
		free_frame(reader_resp);
		return -1;
	}
	SHOW_READER_RESPONSE(reader->dev, reader_resp);
	return 0;
}

int translate_antenna_num(int antenna_code)
{
		if (antenna_code == 1)
			return 1;
		if (antenna_code == 2)
			return 2;
		if (antenna_code == 4)
			return 3;
		if (antenna_code == 8)
			return 4;
		return -1;
}

int parse_inventory_data(struct rfid_reader *reader,
			 struct reader_response *resp,
			 struct inventory_data *inventory)
{
	int off = 0;
	int antenna_num = translate_antenna_num(resp->data[off++]);

	if (antenna_num == -1) {
		dev_err(reader->dev, "Invalid antenna number\n");
		return -1;
	}

	inventory->antenna = (uint8_t)antenna_num;
	inventory->num_tags = resp->data[off++];

	// XXX: Okey so these allocations here are intentionally kinda off and I would like to
	// hear opinions from reviewers on what is the best way to do it.
	//
	// Context: We query the reader, it returns bytes, we want to parse it into
	// struct inventory_data structure
	//
	// Where should this logic live?
	// 1. In kernel driver.
	//  I probably can't do such dynamic allocation like done here in a loop, but instead
	//  should calculate required # of bytes and mmap a continuous memory to put all of
	//  the tags there, so that I could return one pointer to the userspace. Yet then,
	//  userspace code will need to do parsing once again, due to dynamic nature of
	//  response frames length
	//
	// 2. In userspace.
	//  It simplifies the driver code, as the reader already returns continuous memory
	//  will all the data! that lives under resp->data, so maybe the best way would be to
	//  return it to the user, and let him handle the parsing into `struct inventory_data`.
	//
	// 2'. Can I somehow expose to the userspace a function doing the parsing?
	//
	// TODO: consider using devm_kzalloc instead
	inventory->tags = kmalloc_array(inventory->num_tags,
					sizeof(struct inventory_tag *),
					GFP_KERNEL);

	for (int i = 0; i < inventory->num_tags; i++) {
		struct inventory_tag *tag = kmalloc(sizeof(*tag), GFP_KERNEL);

		inventory->tags[i] = tag;

		tag->epc_len = resp->data[off++];

		for (int i = 0; i < tag->epc_len; i++)
			tag->epc[i] = resp->data[off++];

		tag->rssi = resp->data[off++];
	}

	SHOW_INVENTORY_DATA(reader->dev, inventory);

	return 0;
}

void free_inventory_data(struct inventory_data *inventory)
{
	for (int i = 0; i < inventory->num_tags; i++)
		kfree(inventory->tags[i]);
	kfree(inventory->tags);
}

int read_tags(struct rfid_reader *reader, struct file *serial_file)
{
	// Query inventory for the nearest available RFID tags

	struct reader_response reader_resp;
	struct inventory_data inventory;
	u8 data[] = {
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

	struct reader_command inventory_cmd = {
		.addr = 0xFF,
		.cmd = CMD_TAG_INVENTORY,
		.size = sizeof(data),
		.data = data,
	};
	LOG(reader->dev, "Reading RFID tags");

	if (run_command(reader, serial_file, &inventory_cmd, &reader_resp) != 0)
		return -1;

	if (parse_inventory_data(reader, &reader_resp, &inventory) < 0) {
		free_inventory_data(&inventory);
		return -1;
	}

	free_frame(&reader_resp);
	free_inventory_data(&inventory);
	return 0;
}

int set_buzzer(struct rfid_reader *reader, struct file *serial_file, uint8_t value)
{
	// Pass value = 1 to enable buzzer, 0 to disable

	int ret;
	struct reader_response reader_resp;
	struct reader_command cmd = {
		.addr = 0xFF,
		.cmd = CF_SET_BUZZER_ENABLED,
		.size = 1,
		.data = (uint8_t[]) { value },
	};

	ret = run_command(reader, serial_file, &cmd, &reader_resp);
	if (!ret)
		free_frame(&reader_resp);
	return ret;
}

int set_power(struct rfid_reader *reader, struct file *serial_file, uint8_t value)
{
	// Integer value in range [0 - 30]

	int ret;
	struct reader_response reader_resp;
	struct reader_command cmd = {
		.addr = 0xFF,
		.cmd = CF_SET_RF_POWER,
		.size = 1,
		.data = (uint8_t[]) { value },
	};

	if (value > MAX_POWER) {
		dev_err(reader->dev, "Power must be in range 0-%d, was: %d\n", MAX_POWER, value);
		return -1;
	}
	ret = run_command(reader, serial_file, &cmd, &reader_resp);
	if (!ret)
		free_frame(&reader_resp);
	return ret;
}

int set_scan_time(struct rfid_reader *reader, struct file *serial_file, uint8_t value)
{
	// Integer value in range [3 - 255]

	int ret;
	struct reader_response reader_resp;
	struct reader_command cmd = {
		.addr = 0xFF,
		.cmd = CF_SET_READER_INVENTORY_TIME,
		.size = 1,
		.data = (uint8_t[]) { value },
	};

	if (value < MIN_SCAN_TIME) {
		dev_err(reader->dev,
			"Scan time must be in range %d-%d, was: %d\n",
			MIN_SCAN_TIME, MAX_SCAN_TIME, value);
		return -1;
	}

	ret = run_command(reader, serial_file, &cmd, &reader_resp);
	if (!ret)
		free_frame(&reader_resp);
	return ret;
}

MODULE_DESCRIPTION("RFID tags reader");
MODULE_AUTHOR("Mateusz Urbańczyk <urbanczyk@google.com>");
MODULE_LICENSE("GPL");
