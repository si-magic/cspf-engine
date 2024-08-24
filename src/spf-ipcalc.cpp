/**
 * @file spf-ipcalc.cpp
 * @author David Timber (dxdt@dev.snart.me)
 * @brief spf-ipcalc program for testing ipaddress utils
 *
 * @copyright Copyright (c) 2024 David Timber <dxdt@dev.snart.me>
 *
 */
#include "spf-engine/ipaddress.hpp"
#include <iostream>
#include <locale>
#include <string>
#include <algorithm>
#include <cstring>
#include <memory>

int print_help (FILE *out, const char *prog) {
	return fprintf(out,
"SPF Engine ipcalc test\n"
"Usage: %s <OP> [OPRND_A] [OPRND_B]\n"
"  \"PARSE\" just parse and print OPRND_A\n"
"  \"EQUAL\" return 0 if OPRND_A and OPRND_B are equal. Return 1 otherwise\n"
"  \"MATCH\" return 0 if address OPRND_B is in network OPRND_A. Return 1\n"
"            otherwise\n"
"  \"NET\"   parse OPRND_A and print the network address\n"
"  \"HELP\"  print this message and exit normally\n"
"OPRND_A, OPRND_B: IPv4 or v6 address with optional CIDR\n",
		prog);
}

int main (int argc, char **argv) {
	std::string op, oprnd;
	std::unique_ptr<spf::IPPrefix> addr_a, addr_b;

	std::setlocale(LC_ALL, "C");

	for (int i = 1; i < argc; i += 1) {
		try {
			switch (i) {
			case 1:
				// store in all caps
				for (std::size_t j = 0; argv[i][j] != 0; j += 1) {
					argv[i][j] = std::toupper(argv[i][j]);
				}
				op = argv[i];
				break;
			case 2:
				oprnd = argv[i];
				addr_a = std::unique_ptr<spf::IPPrefix>(spf::parse_ip_addr(oprnd));
				break;
			case 3:
				oprnd = argv[i];
				addr_b = std::unique_ptr<spf::IPPrefix>(spf::parse_ip_addr(oprnd));
				break;
			default:
				fprintf(stderr, "Too many arguments.\n");
				return 2;
			}
		}
		catch (std::exception &e) {
			fprintf(stderr, "%s: %s\n", argv[i], e.what());
			return 2;
		}
	}

	if (op == "HELP") {
		print_help(stdout, argv[0]);
		return 0;
	}
	else if (op == "PARSE") {
		if (addr_a == nullptr) {
			fprintf(stderr, "Not enough arguments.\n");
			return 2;
		}
		if (addr_a != nullptr && addr_b != nullptr) {
			fprintf(stderr, "Too many arguments.\n");
			return 2;
		}
		std::cout << addr_a->str() << std::endl;
	}
	else if (op == "EQUAL") {
		if (!(addr_a != nullptr && addr_b != nullptr)) {
			fprintf(stderr, "Not enough arguments.\n");
			return 2;
		}
		if (addr_a->equals(*addr_b)) {
			return 0;
		}
		return 1;
	}
	else if (op == "MATCH") {
		if (!(addr_a != nullptr && addr_b != nullptr)) {
			fprintf(stderr, "Not enough arguments.\n");
			return 2;
		}
		if (addr_a->matches(*addr_b)) {
			return 0;
		}
		return 1;
	}
	else if (op == "NET") {
		if (addr_a == nullptr) {
			fprintf(stderr, "Not enough arguments.\n");
			return 2;
		}
		if (addr_a != nullptr && addr_b != nullptr) {
			fprintf(stderr, "Too many arguments.\n");
			return 2;
		}

		const auto net = addr_a->network();
		std::unique_ptr<spf::IPPrefix> p(spf::ip_addr_from_mem(
			addr_a->ipv(),
			net.data(),
			addr_a->prefix()));

		std::cout << p->str() << std::endl;
	}
	else {
		fprintf(stderr, "Invalid OP. Run `%s HELP` for help.\n", argv[0]);
		return 2;
	}

	return 0;
}
