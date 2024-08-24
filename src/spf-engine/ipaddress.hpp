/**
 * @file ipaddress.hpp
 * @author David Timber (dxdt@dev.snart.me)
 * @brief ipaddress utils header
 *
 * @copyright Copyright (c) 2024 David Timber <dxdt@dev.snart.me>
 *
 */
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <array>
#include <vector>
#include <exception>

namespace spf {

class IPPrefixParseException : public std::exception {
public:
	virtual ~IPPrefixParseException () noexcept;
	virtual const char *what () const noexcept;
};

class IPPrefixNoSupportException : public std::exception {
public:
	virtual ~IPPrefixNoSupportException () noexcept;
	virtual const char *what () const noexcept;
};

class IPPrefixInvalidValueException : public std::exception {
public:
	virtual ~IPPrefixInvalidValueException () noexcept;
	virtual const char *what () const noexcept;
};

class IPPrefix {
protected:
	std::size_t pl;
public:
	virtual ~IPPrefix () noexcept;

	virtual unsigned int ipv () const noexcept = 0;
	std::size_t prefix () const noexcept;
	void prefix (const std::size_t pl);
	virtual bool is_addr () const noexcept = 0;
	virtual bool is_net () const noexcept = 0;
	virtual std::size_t length () const noexcept = 0;
	virtual const std::uint8_t *addr () const noexcept = 0;
	virtual void addr (const uint8_t *src) noexcept = 0;
	virtual bool matches (const IPPrefix &other) const noexcept;
	virtual bool equals (const IPPrefix &other) const noexcept = 0;
	virtual std::string str () const;
	virtual std::vector<uint8_t> network () const noexcept;
};

class IP4Prefix : public IPPrefix {
protected:
	std::array<uint8_t, 4> m;
public:
	virtual ~IP4Prefix () noexcept;

	virtual unsigned int ipv () const noexcept;
	virtual bool is_addr () const noexcept;
	virtual bool is_net () const noexcept;
	virtual std::size_t length () const noexcept;
	virtual const std::uint8_t *addr () const noexcept;
	virtual void addr (const uint8_t *src) noexcept;
	virtual bool equals (const IPPrefix &other) const noexcept;
};


class IP6Prefix : public IPPrefix {
protected:
	std::array<uint8_t, 16> m;
public:
	virtual ~IP6Prefix () noexcept;

	virtual unsigned int ipv () const noexcept;
	virtual bool is_addr () const noexcept;
	virtual bool is_net () const noexcept;
	virtual std::size_t length () const noexcept;
	virtual const std::uint8_t *addr () const noexcept;
	virtual void addr (const uint8_t *src) noexcept;
	virtual bool equals (const IPPrefix &other) const noexcept;
};

std::array<uint8_t, 4> inet_pton4 (const std::string &str);
std::array<uint8_t, 16> inet_pton6 (const std::string &str);
std::vector<uint8_t> parse_ip_addr (const std::string &str, std::size_t &pl);
IPPrefix *parse_ip_addr (const std::string &str);
IPPrefix *ip_addr_from_mem (
	const unsigned int ipv,
	const uint8_t *addr,
	const std::size_t pl);

}
