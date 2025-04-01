#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <string>
#include <cstdint>
#include <arpa/inet.h>
#include <pcap.h>
#include <streambuf>
#include <regex>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iomanip>
#include <sstream>
#include <cstdio>
#include <regex>
#include <iomanip>
#include <vector>
#include <utility>

#define MAC_ADDR_LEN 6

#include "arphdr.h"
#include "ethhdr.h"
#include "ip.h"
#include "mac.h"
