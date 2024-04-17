/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/cdev.h>

#define LOG_ENABLED 1
#define DEBUG_LOG_ENABLED 0

// TODO: Expose all of them to the userspace via generic IOCTL_RUN_COMMAND
enum cmd_type {
	// Action commands
	CMD_TAG_INVENTORY = 0x01,
	CMD_READ_DATA = 0x02,
	CMD_WRITE_DATA = 0x03,
	CMD_WRITE_EPC = 0x04,
	CMD_KILL_TAG = 0x05,
	CMD_SET_PROTECTION = 0x06,
	CMD_ERASE_BLOCK = 0x07,
	CMD_READ_PROTECTION_EPC = 0x08,
	CMD_READ_PROTECTION_NO_EPC = 0x09,
	CMD_UNLOCK_READ_PROTECTION = 0x0a,
	CMD_READ_PROTECTION_STATUS_CHECK = 0x0b,
	CMD_EAS_CONFIGURATION = 0x0c,
	CMD_EAS_ALERT_DETECTION = 0x0d,
	CMD_SINGLE_TAG_INVENTORY = 0x0f,
	CMD_WRITE_BLOCKS = 0x10,
	CMD_GET_MONZA_4QT_WORKING_PARAMETERS = 0x11,
	CMD_SET_MONZA_4QT_WORKING_PARAMETERS = 0x12,
	CMD_READ_EXTENDED_DATA = 0x15,
	CMD_WRITE_EXTENDED_DATA = 0x16,
	CMD_TAG_INVENTORY_WITH_MEMORY_BUFFER = 0x18,
	CMD_MIX_INVENTORY = 0x19,
	CMD_INVENTORY_EPC = 0x1a,
	CMD_QT_INVENTORY = 0x1b,

	// Config commands
	CF_GET_READER_INFO = 0x21,
	CF_SET_WORKING_FREQUENCY = 0x22,
	CF_SET_READER_ADDRESS = 0x24,
	CF_SET_READER_INVENTORY_TIME = 0x25,
	CF_SET_SERIAL_BAUD_RATE = 0x28,
	CF_SET_RF_POWER = 0x2f,
	CF_SET_WORK_MODE_288M = 0x76,
	CF_SET_WORK_MODE_18 = 0x35,
	CF_SET_BUZZER_ENABLED = 0x40,
	CF_SET_ACCOUSTO_OPTIC_TIMES = 0x33
};

// Constants
#define CMD_RESPONSE_BUFFER_SIZE 256
#define CRC_POLYNOMIAL 0x8408
#define INITIAL_CRC 0xFFFF

// Constraints
#define MAX_POWER 30
#define MAX_SCAN_TIME 0xFF
#define MIN_SCAN_TIME 0x03
#define EPC_MAX_LEN 256

#if LOG_ENABLED
	#define LOG_ENTRY_LINE(...) \
		printk(KERN_NOTICE "[%s:%d] %s: ", __FILE__, __LINE__, __func__)
#else
	#define LOG_ENTRY_LINE(...) do { } while (0)
#endif

#if LOG_ENABLED
	#define LOG_NO_NEWLINE(...) \
		do { \
			LOG_ENTRY_LINE(); \
			printk(KERN_NOTICE __VA_ARGS__); \
		} while (0)
#else
	#define LOG_NO_NEWLINE(...) do { } while (0)
#endif

#if LOG_ENABLED
	#define LOG(...) \
		do { \
			LOG_NO_NEWLINE(__VA_ARGS__); \
			printk(KERN_NOTICE "\n"); \
		} while (0)
#else
	#define LOG(...) do { } while (0)
#endif

#if LOG_ENABLED
	#define SECTION_LOG(...) \
		do { \
			LOG_ENTRY_LINE(); \
			printk(KERN_NOTICE "-----"); \
			printk(KERN_NOTICE __VA_ARGS__); \
			printk(KERN_NOTICE "-----"); \
			printk(KERN_NOTICE "\n"); \
		} while (0)
#else
	#define SECTION_LOG(...) do { } while (0)
#endif

#if LOG_ENABLED
	#define QUIET_LOG(...) printk(KERN_NOTICE __VA_ARGS__)
#else
	#define QUIET_LOG(...) do { } while (0)
#endif

#define SHOW_BUFFER_CONTENTS(buffer, size) \
	do { \
		for (ssize_t i = 0; i < (size); i++) { \
			QUIET_LOG("%02X ", (buffer)[i]); \
		} \
	} while (0)

#define SHOW_BUFFER(action, buffer, size) \
	do { \
		typeof(size) _size = size; \
		LOG_NO_NEWLINE("%s %zd bytes: ", action, _size); \
		SHOW_BUFFER_CONTENTS((buffer), _size); \
		QUIET_LOG("\n"); \
	} while (0)

struct reader_command {
	u8 addr;
	enum cmd_type cmd;
	u8 size;
	u8 *data;
};

struct reader_response {
	u8 size;
	u8 reader_addr;
	u8 resp_cmd;
	u8 status;
	u8 *data;
};

struct inventory_tag {
	u8 rssi;
	u8 epc_len;
	u8 epc[EPC_MAX_LEN];
};

struct inventory_data {
	u8 antenna;
	u8 num_tags;
	struct inventory_tag **tags;
};

#define SHOW_READER_COMMAND(cmd) \
	do { \
		typeof(cmd) _cmd = cmd; \
		LOG("<ReaderCommand: addr=0x%02X, cmd=0x%02X, size=0x%02X >", \
			(_cmd)->addr, (_cmd)->_cmd, (_cmd)->size); \
		if ((_cmd)->size) { \
			SHOW_BUFFER("Reader command data has", \
				    (_cmd)->data, \
				    (ssize_t)(_cmd)->size); \
		} \
	} while (0)

#define SHOW_READER_RESPONSE(cmd) \
	do { \
		typeof(cmd) _cmd = cmd; \
		LOG("<ReaderResponse: size=0x%02X, addr=0x%02X, resp_cmd=0x%02X, status=0x%02X >", \
			(_cmd)->size, (_cmd)->reader_addr, (_cmd)->resp__cmd, (_cmd)->status); \
		if ((_cmd)->size) { \
			SHOW_BUFFER("Received response of", (_cmd)->data, (ssize_t)(_cmd)->size); \
		} \
	} while (0)

#define SHOW_INVENTORY_TAG(tag) \
	do { \
		typeof(tag) _tag = tag; \
		if (searched_epc_len > 0 && \
			(memcmp((_tag)->epc, searched_epc, searched_epc_len) == 0)) { \
			QUIET_LOG("[*FOUND*]"); \
		} \
		QUIET_LOG("<Tag: "); \
		QUIET_LOG("rssi=%u, ", (_tag)->rssi); \
		QUIET_LOG("epc_len=%u, ", (_tag)->epc_len); \
		QUIET_LOG("epc="); \
		for (size_t i = 0; i < (_tag)->epc_len; ++i) { \
			QUIET_LOG("%02X ", (_tag)->epc[i]); \
		} \
		QUIET_LOG(">\n"); \
	} while (0)

#define SHOW_INVENTORY_DATA(inv) \
	do { \
		typeof(inv) _inv = inv; \
		QUIET_LOG("<Inventory Data: "); \
		QUIET_LOG("Antenna=%u, ", (_inv)->antenna); \
		QUIET_LOG("#Tags=%u>\n", (_inv)->num_tags); \
		for (size_t i = 0; i < (_inv)->num_tags; ++i) { \
			QUIET_LOG("[%zu] ", i + 1); \
			SHOW_INVENTORY_TAG((_inv)->tags[i]); \
		} \
	} while (0)

#define CRC_MSB(crc) ((crc) >> 8)
#define CRC_LSB(crc) ((crc) & 0xFF)

uint16_t crc_checksum(u8 *data, int len);

int write_frame(struct file *serial_file, struct reader_command *cmd);

ssize_t read_frame(struct file *serial_file, uint8_t *buffer);

int verify_checksum(u8 *data, ssize_t data_len, uint8_t *checksum_bytes);

int parse_frame(u8 *buffer, ssize_t buffer_size, struct reader_response *frame);

void free_frame(struct reader_response *frame);

int run_command(struct file *serial_file,
		struct reader_command *cmd,
		struct reader_response *reader_resp);

int set_buzzer(struct file *serial_file, uint8_t value);

int set_power(struct file *serial_file, uint8_t value);

int set_scan_time(struct file *serial_file, uint8_t value);

int translate_antenna_num(int antenna_code);

int parse_inventory_data(struct reader_response *resp,
			 struct inventory_data *inventory);

void free_inventory_data(struct inventory_data *inventory);

int read_tags(struct file *serial_file);
