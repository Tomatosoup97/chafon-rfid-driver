#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/cdev.h>

#define LOG_ENABLED 1
#define DEBUG_LOG_ENABLED 0

// TODO: Expose all of them to the userspace via generic IOCTL_RUN_COMMAND
typedef enum {
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
} CmdType;


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
        do { \
            printk(KERN_NOTICE "[%s:%d] %s: ", __FILE__, __LINE__, __func__); \
        } while (0)
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
    #define QUIET_LOG(...) \
        do { \
            printk(KERN_NOTICE __VA_ARGS__); \
        } while (0)
#else
    #define QUIET_LOG(...) do { } while (0)
#endif

#define SHOW_BUFFER_CONTENTS(buffer, size) \
    do { \
        for (ssize_t i = 0; i < size; i++) { \
            QUIET_LOG("%02X ", (buffer)[i]); \
        } \
    } while (0)

#define SHOW_BUFFER(action, buffer, size) \
    do { \
        LOG_NO_NEWLINE("%s %zd bytes: ", action, size); \
        SHOW_BUFFER_CONTENTS((buffer), size); \
        QUIET_LOG("\n"); \
    } while (0)


typedef struct {
  uint8_t addr;
  CmdType cmd;
  uint8_t size;
  uint8_t *data;
} reader_command_t;

typedef struct {
  uint8_t size;
  uint8_t reader_addr;
  uint8_t resp_cmd;
  uint8_t status;
  uint8_t *data;
} reader_response_t;

typedef struct {
  uint8_t rssi;
  uint8_t epc_len;
  uint8_t epc[EPC_MAX_LEN];
} inventory_tag_t;

typedef struct {
  uint8_t antenna;
  uint8_t num_tags;
  inventory_tag_t **tags;
} inventory_data_t;

#define SHOW_READER_COMMAND(cmd) \
    do { \
        LOG("<ReaderCommand: addr=0x%02X, cmd=0x%02X, size=0x%02X >", \
            (cmd)->addr, (cmd)->cmd, (cmd)->size); \
        if ((cmd)->size) { \
          SHOW_BUFFER("Reader command data has", (cmd)->data, (ssize_t) (cmd)->size); \
        } \
    } while (0)


#define SHOW_READER_RESPONSE(cmd) \
    do { \
        LOG("<ReaderResponse: size=0x%02X, reader_addr=0x%02X, resp_cmd=0x%02X, status=0x%02X >", \
            (cmd)->size, (cmd)->reader_addr, (cmd)->resp_cmd, (cmd)->status); \
        if ((cmd)->size) { \
          SHOW_BUFFER("Received response of", (cmd)->data, (ssize_t) (cmd)->size); \
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

uint16_t crc_checksum(uint8_t *data, int len);

int write_frame(struct file *serial_file, reader_command_t *cmd);

ssize_t read_frame(struct file *serial_file, uint8_t *buffer);

int verify_checksum(uint8_t *data, ssize_t data_len, uint8_t *checksum_bytes);

int parse_frame(uint8_t *buffer, ssize_t buffer_size, reader_response_t *frame);

void free_frame(reader_response_t *frame);

int run_command(
    struct file *serial_file,
    reader_command_t *cmd,
    reader_response_t *reader_resp
);

int set_buzzer(struct file *serial_file, uint8_t value);

int set_power(struct file *serial_file, uint8_t value);

int set_scan_time(struct file *serial_file, uint8_t value);

int translate_antenna_num(int antenna_code);

int parse_inventory_data(
  reader_response_t *resp,
  inventory_data_t *inventory
);

void free_inventory_data(inventory_data_t *inventory);

int read_tags(struct file *serial_file);
