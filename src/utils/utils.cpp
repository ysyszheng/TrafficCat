#include "utils.h"

// Print the payload in hexadecimal
void print_payload(const u_char *payload, size_t payload_len) {
  size_t offset = 0;
  size_t cnt = 0;
  u_char str[17];
  while (offset < payload_len) {
    // Print the offset in hexadecimal
    printf("%05zx  ", offset);
    // Copy the payload bytes to str
    while (cnt < payload_len && cnt - offset < 16) {
      str[cnt - offset] = *(payload + cnt);
      cnt++;
    }
    // Null-terminate the string
    str[cnt - offset] = '\0';
    for (size_t i = 0; i < 16; i++) {
      if (i < cnt - offset) {
        // Print the hexadecimal representation of the byte
        printf("%02x", str[i]);
      } else {
        // Print empty spaces for padding
        printf("  ");
      }
      if (i == 7 || i == 15) {
        // Print an additional space after the 8th and 16th bytes
        printf("  ");
      } else {
        // Print a space between each byte
        printf(" ");
      }
    }
    for (size_t i = 0; i < 16; i++) {
      if (i < cnt - offset) {
        if (isprint(str[i])) {
          // Print the ASCII character if printable
          printf("%c", str[i]);
        } else {
          // Print a dot if not printable
          printf(".");
        }
      } else {
        // Print an empty space for padding
        printf(" ");
      }
      if (i == 7) {
        // Print an additional space after the 8th byte
        printf("  ");
      }
    }
    offset += 16;
    printf("\n");
  }
}

// Store the payload in hexadecimal
std::string store_payload(const u_char *payload, long payload_len) {
  std::string data;
  size_t offset = 0;
  size_t cnt = 0;
  u_char str[17];
  char buffer[64];

  while (offset < payload_len) {
    // Print the offset in hexadecimal
    sprintf(buffer, "%05zx  ", offset);
    data += buffer;
    // Copy the payload bytes to str
    while (cnt < payload_len && cnt - offset < 16) {
      str[cnt - offset] = *(payload + cnt);
      cnt++;
    }

    // Null-terminate the string
    str[cnt - offset] = '\0';
    for (size_t i = 0; i < 16; i++) {
      if (i < cnt - offset) {
        // Format the byte as a two-digit hexadecimal string
        sprintf(buffer, "%02x", str[i]);
        data += buffer;
      } else {
        // Format empty spaces for padding
        sprintf(buffer, "  ");
        data += buffer;
      }
      if (i == 7 || i == 15) {
        // Format an additional space after the 8th and 16th bytes
        sprintf(buffer, "  ");
        data += buffer;
      } else {
        // Format a space between each byte
        sprintf(buffer, " ");
        data += buffer;
      }
    }
    for (size_t i = 0; i < 16; i++) {
      if (i < cnt - offset) {
        if (isprint(str[i])) {
          // Format the ASCII character if printable
          sprintf(buffer, "%c", str[i]);
          data += buffer;
        } else {
          // Format a dot if not printable
          sprintf(buffer, ".");
          data += buffer;
        }
      } else {
        // Format an empty space for padding
        sprintf(buffer, " ");
        data += buffer;
      }
      if (i == 7) {
        // Format an additional space after the 8th byte
        sprintf(buffer, "  ");
        data += buffer;
      }
    }
    offset += 16;
    sprintf(buffer, "\n");
    data += buffer;
  }

  return data;
}

// Print the payload in ASCII
std::string store_content(const u_char *payload, long payload_len) {
  std::string data;
  int cnt = 0;
  char buffer[64];

  // Print the payload data
  while (cnt < payload_len) {
    if (isprint(payload[cnt])) {
      // Print the ASCII character if printable
      sprintf(buffer, "%c", payload[cnt]);
      data += buffer;
    } else {
      // Print a dot if not printable
      sprintf(buffer, " ");
      data += buffer;
    }
    cnt++;
  }

  return data;
}

// Print the payload in ASCII
const std::string currentDataTime() {
  time_t now = time(NULL);
  struct tm tstruct;
  char buf[80];
  tstruct = *localtime(&now);
  // Format the current date and time
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tstruct);
  return buf;
}
// Compare the IP offsets
bool ipcmp(const packet_struct *p1, const packet_struct *p2) {
  return ((ntohs(p1->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) <
          (ntohs(p2->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
}