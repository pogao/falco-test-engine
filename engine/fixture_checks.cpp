#include "fixture_checks.h"

#include <libsinsp/plugin.h>
#include <libsinsp/plugin_manager.h>
#include <libsinsp/value_parser.h>

#include <algorithm>
#include <cstring>

encoded_value encode_value(ppm_param_type type, const std::string& str) {
	// network fields extract an address and compare it against the network on the rhs
	switch(type) {
	case PT_IPNET:
		type = PT_IPADDR;
		break;
	case PT_IPV4NET:
		type = PT_IPV4ADDR;
		break;
	case PT_IPV6NET:
		type = PT_IPV6ADDR;
		break;
	default:
		break;
	}

	encoded_value v;
	v.buf.resize(std::max<size_t>(16, str.size() + 1));
	if(type == PT_BYTEBUF) {
		memcpy(v.buf.data(), str.data(), str.size());
		v.len = str.size();
		return v;
	}
	// same grow-and-retry as sinsp_filter_check::add_filter_value, without its 256-byte cap on
	// strings, which only bounds rule constants
	while(true) {
		try {
			v.len = sinsp_filter_value_parser::string_to_rawval(str.c_str(),
			                                                    str.size(),
			                                                    v.buf.data(),
			                                                    v.buf.size(),
			                                                    type);
			return v;
		} catch(const sinsp_exception&) {
			if(v.buf.size() >= 256) {
				throw;
			}
			v.buf.resize(v.buf.size() * 2);
		}
	}
}

static std::vector<std::string> field_names(const filter_check_list& list) {
	std::vector<const filter_check_info*> infos;
	list.get_all_fields(infos);
	std::vector<std::string> names;
	for(const auto* info : infos) {
		for(int32_t i = 0; i < info->m_nfields; i++) {
			names.push_back(info->m_fields[i].m_name);
		}
	}
	return names;
}

fixture_check_list::fixture_check_list(fixture_context& ctx, sinsp& inspector) {
	// mirrors sinsp_filter_check_list's constructor
	add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_gen_event>>(ctx));
	add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_event>>(ctx));
	add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_thread>>(ctx));
	add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_user>>(ctx));
	add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_group>>(ctx));
	add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_fd>>(ctx));
	add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_fspath>>(ctx));
	add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_utils>>(ctx));
	add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_fdlist>>(ctx));

	if(field_names(*this) != field_names(sinsp_filter_check_list())) {
		throw sinsp_exception(
		        "fixture filterchecks diverge from sinsp_filter_check_list; update "
		        "fixture_check_list for this libs version");
	}

	// mirrors populate_filterchecks in Falco's init_inspectors.cpp
	for(const auto& plugin : inspector.get_plugin_manager()->plugins()) {
		if(!(plugin->caps() & CAP_EXTRACTION)) {
			continue;
		}
		auto existing = field_names(*this);
		for(const auto& field : plugin->fields()) {
			if(std::find(existing.begin(), existing.end(), field.m_name) != existing.end()) {
				throw sinsp_exception("Plugin '" + plugin->name() +
				                      "' supports extraction of field '" + field.m_name +
				                      "' that is overlapping for source 'syscall'");
			}
		}
		add_filter_check(std::make_unique<fixture_check<sinsp_filter_check_plugin>>(ctx, plugin));
	}
}
