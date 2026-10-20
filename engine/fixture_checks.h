#pragma once

#include <libsinsp/filter_check_list.h>
#include <libsinsp/filterchecks.h>
#include <libsinsp/plugin_filtercheck.h>
#include <libsinsp/sinsp.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <type_traits>
#include <vector>

using case_fields = std::map<std::string, std::vector<std::string>>;

// The case under evaluation, read by every fixture check. Single-threaded.
struct fixture_context {
	const case_fields* fields = nullptr;
	std::set<std::string> missing;

	const std::vector<std::string>* lookup(const std::string& name) {
		if(fields != nullptr) {
			auto it = fields->find(name);
			if(it != fields->end() && !it->second.empty()) {
				return &it->second;
			}
		}
		missing.insert(name);
		return nullptr;
	}
};

struct encoded_value {
	std::vector<uint8_t> buf;
	uint32_t len = 0;
};

// Converts a case string to the binary form a real extraction of a field of this type returns.
// Throws sinsp_exception when the string does not parse as that type.
encoded_value encode_value(ppm_param_type type, const std::string& str);

// Wraps a libsinsp filtercheck so that values come from the current case. Field parsing,
// transformers, and comparison stay libsinsp's.
template<class Real>
class fixture_check : public Real {
public:
	template<class... Args>
	explicit fixture_check(fixture_context& ctx, Args&&... args):
	        Real(std::forward<Args>(args)...),
	        m_ctx(ctx) {}

	std::unique_ptr<sinsp_filter_check> allocate_new() override {
		if constexpr(std::is_same_v<Real, sinsp_filter_check_plugin>) {
			// the plugin check carries its plugin, which only the copy constructor transfers
			return std::make_unique<fixture_check>(*this);
		} else {
			return std::make_unique<fixture_check>(m_ctx);
		}
	}

	int32_t parse_field_name(std::string_view str,
	                         bool alloc_state,
	                         bool needed_for_filtering) override {
		int32_t len = Real::parse_field_name(str, alloc_state, needed_for_filtering);
		if(len > 0) {
			m_name = std::string(str.substr(0, len));
		}
		return len;
	}

protected:
	bool extract_nocache(sinsp_evt*,
	                     std::vector<extract_value_t>& values,
	                     std::vector<extract_offset_t>* offsets) override {
		values.clear();
		if(offsets != nullptr) {
			offsets->clear();
		}
		const auto* strs = m_ctx.lookup(m_name);
		if(strs == nullptr) {
			return false;
		}
		encode(strs->data(), strs->data() + strs->size(), values);
		if(offsets != nullptr) {
			offsets->resize(values.size());
		}
		return true;
	}

	// Never delegates to Real::compare_nocache: the thread and fd checks override it to walk live
	// thread and fd state (proc.aname and friends, fd.ip/port/net/proto). Several values for a
	// non-list field reproduce that "any of" semantics.
	bool compare_nocache(sinsp_evt* evt) override {
		const auto* strs = m_ctx.lookup(m_name);
		const auto* info = this->get_transformed_field_info();
		if(strs == nullptr || strs->size() < 2 || info->is_list() || this->has_filtercheck_value()) {
			return sinsp_filter_check::compare_nocache(evt);
		}
		for(const auto& s : *strs) {
			encode(&s, &s + 1, this->m_extracted_values);
			if(this->apply_transformers(this->m_extracted_values) &&
			   this->compare_rhs(this->m_cmp, info->m_type, this->m_extracted_values)) {
				return true;
			}
		}
		return false;
	}

	Json::Value extract_as_js(sinsp_evt*, uint32_t*) override { return Json::nullValue; }

private:
	void encode(const std::string* begin,
	            const std::string* end,
	            std::vector<extract_value_t>& values) {
		values.clear();
		m_storage.clear();
		m_storage.reserve(end - begin);
		auto type = this->get_field_info()->m_type;
		for(auto s = begin; s != end; ++s) {
			auto& v = m_storage.emplace_back(encode_value(type, *s));
			values.push_back({v.buf.data(), v.len});
		}
	}

	fixture_context& m_ctx;
	std::string m_name;
	std::vector<encoded_value> m_storage;
};

// sinsp_filter_check_list with every check wrapped, plus the extraction checks of the
// inspector's plugins, as Falco populates them for the syscall source.
class fixture_check_list : public filter_check_list {
public:
	fixture_check_list(fixture_context& ctx, sinsp& inspector);
};
