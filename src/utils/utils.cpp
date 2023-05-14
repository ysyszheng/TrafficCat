#include "utils.h"

void print_payload(const u_char *payload, size_t payload_len) {
  size_t offset = 0;
  size_t cnt = 0;
  u_char str[17];
  while (offset < payload_len) {
    printf("%05zx  ", offset);
    while (cnt < payload_len && cnt - offset < 16) {
      str[cnt - offset] = *(payload + cnt);
      cnt++;
    }
    str[cnt - offset] = '\0';
    for (size_t i = 0; i < 16; i++) {
      if (i < cnt - offset) {
        printf("%02x", str[i]);
      } else {
        printf("  ");
      }
      if (i == 7 || i == 15) {
        printf("  ");
      } else {
        printf(" ");
      }
    }
    for (size_t i = 0; i < 16; i++) {
      if (i < cnt - offset) {
        if (isprint(str[i])) {
          printf("%c", str[i]);
        } else {
          printf(".");
        }
      } else {
        printf(" ");
      }
      if (i == 7) {
        printf("  ");
      }
    }
    offset += 16;
    printf("\n");
  }
}

std::string store_payload(const u_char *payload, long payload_len) {
  std::string data;
  size_t offset = 0;
  size_t cnt = 0;
  u_char str[17];
  char buffer[64];

  while (offset < payload_len) {
    sprintf(buffer, "%05zx  ", offset);
    data += buffer;
    while (cnt < payload_len && cnt - offset < 16) {
      str[cnt - offset] = *(payload + cnt);
      cnt++;
    }
    str[cnt - offset] = '\0';
    for (size_t i = 0; i < 16; i++) {
      if (i < cnt - offset) {
        sprintf(buffer, "%02x", str[i]);
        data += buffer;
      } else {
        sprintf(buffer, "  ");
        data += buffer;
      }
      if (i == 7 || i == 15) {
        sprintf(buffer, "  ");
        data += buffer;
      } else {
        sprintf(buffer, " ");
        data += buffer;
      }
    }
    for (size_t i = 0; i < 16; i++) {
      if (i < cnt - offset) {
        if (isprint(str[i])) {
          sprintf(buffer, "%c", str[i]);
          data += buffer;
        } else {
          sprintf(buffer, ".");
          data += buffer;
        }
      } else {
        sprintf(buffer, " ");
        data += buffer;
      }
      if (i == 7) {
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

std::string store_content(const u_char *payload, long payload_len) {
  std::string data;
  int cnt = 0;
  char buffer[64];

  while (cnt < payload_len) {
    if (isprint(payload[cnt])) {
      sprintf(buffer, "%c", payload[cnt]);
      data += buffer;
    } else {
      sprintf(buffer, " ");
      data += buffer;
    }
    cnt++;
  }

  return data;
}

const std::string currentDataTime() {
  time_t now = time(NULL);
  struct tm tstruct;
  char buf[80];
  tstruct = *localtime(&now);
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tstruct);
  return buf;
}

bool ipcmp(const packet_struct *p1, const packet_struct *p2) {
  return ((ntohs(p1->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) <
          (ntohs(p2->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
}