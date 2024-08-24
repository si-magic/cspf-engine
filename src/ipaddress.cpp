/**
 * @file ipaddress.hpp
 * @author David Timber (dxdt@dev.snart.me)
 * @brief ipaddress utils impl
 *
 * @copyright Copyright (c) 2024 David Timber <dxdt@dev.snart.me>
 *
 */
#include "spf-engine/ipaddress.hpp"
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <cerrno>
#include <sstream>

namespace spf {

/* static */

static std::vector<uint8_t> mk_bitmask (
		const std::size_t addr_len,
		std::size_t prefix_len)
{
	std::vector<uint8_t> ret;
	std::size_t i, p;

	if (addr_len * 8 < prefix_len) {
		throw IPPrefixInvalidValueException();
	}

	ret.resize(addr_len);

	for (i = 0; prefix_len >= 8; prefix_len -= 8, i += 1) {
		ret[i] = 0xff;
	}
	p = i;
	for (i = 0; i < prefix_len; i += 1) {
		ret[p] = (ret[p] << 1) | 1;
	}

	return ret;
}

static std::vector<uint8_t> bitmask_and (
		const std::size_t addr_len,
		const uint8_t *a,
		const uint8_t *b)
{
	std::vector<uint8_t> ret(addr_len);

	for (std::size_t i = 0; i < addr_len; i += 1) {
		ret[i] = a[i] & b[i];
	}

	return ret;
}

static constexpr std::size_t get_addrstrlen (const unsigned int ipv) noexcept {
	switch (ipv) {
	case 4: return INET_ADDRSTRLEN;
	case 6: return INET6_ADDRSTRLEN;
	}
	abort();
}

static constexpr int get_addrfamily (const unsigned int ipv) noexcept {
	switch (ipv) {
	case 4: return AF_INET;
	case 6: return AF_INET6;
	}
	abort();
}

/* IPPrefixException */

IPPrefixParseException::~IPPrefixParseException () {}
const char *IPPrefixParseException::what () const noexcept {
	return "spf::IPPrefixParseException";
}

/* IPPrefixNoSupportException */

IPPrefixNoSupportException::~IPPrefixNoSupportException () {}
const char *IPPrefixNoSupportException::what () const noexcept {
	return "spf::IPPrefixNoSupportException";
}

/* IPPrefixInvalidValueException */

IPPrefixInvalidValueException::~IPPrefixInvalidValueException () {}
const char *IPPrefixInvalidValueException::what () const noexcept {
	return "spf::IPPrefixInvalidValueException";
}

/* IPPrefix */

IPPrefix::~IPPrefix () {}

std::size_t IPPrefix::prefix () const noexcept {
	return this->pl;
}

void IPPrefix::prefix (const std::size_t pl) {
	if (pl > this->length() * 8) {
		throw IPPrefixInvalidValueException();
	}

	this->pl = pl;
}

bool IPPrefix::matches (const IPPrefix &other) const noexcept {
	if (this->ipv() != other.ipv()) {
		return false;
	}
	const auto al = this->length();
	const auto mask = mk_bitmask(al, this->pl);

	return bitmask_and(al, other.addr(), mask.data()) == this->network();
}

std::string IPPrefix::str () const {
	const auto ipv = this->ipv();
	const auto prefix = this->prefix();
	std::string buf(get_addrstrlen(ipv), 0);
	const char *fr;

	fr = inet_ntop(get_addrfamily(ipv), this->addr(), buf.data(), buf.size());
	if (fr == nullptr) {
		throw IPPrefixNoSupportException();
	}

	if (prefix != 8 * this->length()) {
		std::stringstream ss;
		// STL might get confused over the null character at the end so c_str()
		// is used.
		ss << buf.c_str() << "/" << prefix;
		return ss.str();
	}

	return buf;
}

std::vector<uint8_t> IPPrefix::network () const noexcept {
	const auto al = this->length();
	const auto mask = mk_bitmask(al, this->pl);
	return bitmask_and(al, mask.data(), this->addr());
}

/* IP4Prefix */
IP4Prefix::~IP4Prefix () {}

unsigned int IP4Prefix::ipv () const noexcept {
	return 4;
}

bool IP4Prefix::is_addr () const noexcept {
	return this->pl == 32;
}

bool IP4Prefix::is_net () const noexcept {
	return this->pl < 32;
}

std::size_t IP4Prefix::length () const noexcept {
	return this->m.size();
}

const std::uint8_t *IP4Prefix::addr () const noexcept {
	return this->m.data();
}

void IP4Prefix::addr (const uint8_t *src) noexcept {
	memcpy(this->m.data(), src, this->m.size());
}

bool IP4Prefix::equals (const IPPrefix &other) const noexcept {
	return
		other.length() == 4 &&
		IPPrefix::prefix() == other.prefix() &&
		memcmp(this->addr(), other.addr(), 4) == 0;
}

/* IP6Prefix */
IP6Prefix::~IP6Prefix () {}

unsigned int IP6Prefix::ipv () const noexcept {
	return 6;
}

bool IP6Prefix::is_addr () const noexcept {
	return this->pl == 128;
}

bool IP6Prefix::is_net () const noexcept {
	return this->pl < 128;
}

std::size_t IP6Prefix::length () const noexcept {
	return this->m.size();
}

const std::uint8_t *IP6Prefix::addr () const noexcept {
	return this->m.data();
}

void IP6Prefix::addr (const uint8_t *src) noexcept {
	memcpy(this->m.data(), src, this->m.size());
}

bool IP6Prefix::equals (const IPPrefix &other) const noexcept {
	return
		other.length() == 16 &&
		IPPrefix::prefix() == other.prefix() &&
		memcmp(this->addr(), other.addr(), 16) == 0;
}

/* others */
std::array<uint8_t, 4> inet_pton4 (const std::string &str) {
	std::array<uint8_t, 4> ret;
	const int fr = inet_pton(AF_INET, str.c_str(), ret.data());

	if (fr == 0) {
		throw IPPrefixParseException();
	}
	if (fr < 0) {
		throw IPPrefixNoSupportException();
	}

	return ret;
}

std::array<uint8_t, 16> inet_pton6 (const std::string &str) {
	std::array<uint8_t, 16> ret;
	const int fr = inet_pton(AF_INET6, str.c_str(), ret.data());

	if (fr == 0) {
		throw IPPrefixParseException();
	}
	if (fr < 0) {
		throw IPPrefixNoSupportException();
	}

	return ret;
}

std::vector<uint8_t> parse_ip_addr (const std::string &str, std::size_t &pl) {
	std::vector<uint8_t> ret;
	const auto slash_first = str.find_first_of('/');
	const auto slash_last = str.find_first_of('/');
	std::string cidr_part, addr_part;
	std::size_t full_len;

	if (slash_first != std::string::npos && slash_last != std::string::npos) {
		// slash should only appear once
		if (slash_first != slash_last) {
			throw IPPrefixParseException();
		}
		// there's one slash
		// this is a network address
		addr_part = str.substr(0, slash_first);
		cidr_part = str.substr(slash_first + 1);
	}
	else {
		// there's no slash
		// this is a host address
		addr_part = str;
	}

	try {
		const auto parsed = inet_pton4(addr_part);
		ret.reserve(4);
		ret.assign(parsed.begin(), parsed.end());
		assert(ret.size() == 4);
	}
	catch (IPPrefixParseException &) {
		const auto parsed = inet_pton6(addr_part);
		ret.reserve(16);
		ret.assign(parsed.begin(), parsed.end());
		assert(ret.size() == 16);
	}

	full_len = ret.size() * 8;
	if (cidr_part.empty()) {
		pl = full_len;
	}
	else {
		std::istringstream iss(cidr_part);

		iss >> pl;
		if (iss.fail() || pl > full_len) {
			throw IPPrefixParseException();
		}
	}

	return ret;
}

IPPrefix *parse_ip_addr (const std::string &str) {
	std::size_t pl;
	const auto buf = parse_ip_addr(str, pl);
	IPPrefix *ret = nullptr;

	switch (buf.size()) {
	case 4: ret = new IP4Prefix(); break;
	case 16: ret = new IP6Prefix(); break;
	}

	if (ret == nullptr) {
		assert(ret != nullptr);
		abort();
	}

	ret->addr(buf.data());
	ret->prefix(pl);
	return ret;
}

IPPrefix *ip_addr_from_mem (
		const unsigned int ipv,
		const uint8_t *addr,
		const std::size_t pl)
{
	IPPrefix *ret = nullptr;

	switch (ipv) {
	case 4: ret = new IP4Prefix(); break;
	case 6: ret = new IP6Prefix(); break;
	default: throw IPPrefixInvalidValueException();
	}

	ret->addr(addr);
	ret->prefix(pl);

	return ret;
}

}
