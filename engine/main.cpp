#include "ast_json.h"
#include "fixture_checks.h"

#include <config_falco.h>
#include <falco_engine.h>
#include <rule_loader_collector.h>

#include <libsinsp/events/sinsp_events.h>
#include <libsinsp/filter/parser.h>
#include <libsinsp/plugin_manager.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>

using nlohmann::json;

// Falco keys plugins by the library's own name, so the job's plugin name is not read.
struct plugin_spec {
	std::string library_path;
	std::string init_config;
};

struct test_case {
	std::string id;
	std::string source;
	case_fields fields;
	std::vector<std::string> trace_rules;
};

struct job {
	std::vector<std::string> rules_files;
	std::vector<plugin_spec> plugins;
	bool describe = false;
	std::vector<test_case> cases;
};

static job parse_job(const json& j) {
	job out;
	out.rules_files = j.at("rules_files").get<std::vector<std::string>>();
	for(const auto& p : j.value("plugins", json::array())) {
		out.plugins.push_back(
		        {p.at("library_path").get<std::string>(), p.value("init_config", std::string())});
	}
	out.describe = j.value("describe", false);
	for(const auto& c : j.value("cases", json::array())) {
		out.cases.push_back({c.at("id").get<std::string>(),
		                     c.value("source", std::string(falco_common::syscall_source)),
		                     c.at("fields").get<case_fields>(),
		                     c.value("trace_rules", std::vector<std::string>())});
	}
	return out;
}

static std::string read_file(const std::string& path) {
	std::ifstream in(path);
	if(!in) {
		throw std::runtime_error("can't read file " + path);
	}
	std::stringstream ss;
	ss << in.rdbuf();
	return ss.str();
}

// Falco substitutes lists into the condition text before parsing, so a condition can compile
// while its raw text does not parse on its own.
static json raw_ast(const std::string& condition) {
	libsinsp::filter::parser parser(condition);
	parser.set_max_depth(1000);
	try {
		return ast_to_json(parser.parse().get());
	} catch(const sinsp_exception&) {
		return nullptr;
	}
}

static std::string priority_name(falco_common::priority_type p) {
	auto s = falco_common::format_priority(p);
	std::transform(s.begin(), s.end(), s.begin(), ::toupper);
	return s;
}

static json sorted(const std::unordered_set<std::string>& names) {
	std::vector<std::string> v(names.begin(), names.end());
	std::sort(v.begin(), v.end());
	return v;
}

// Rules index every direction and version of an event, so any code for the name reaches the same
// rules. The newest exit event is the one a live kernel would produce.
static std::optional<ppm_event_code> event_code(const std::string& name) {
	auto rank = [](ppm_event_code c) {
		return (PPME_IS_EXIT(c) ? 2 : 0) + (libsinsp::events::is_old_version_event(c) ? 0 : 1);
	};
	std::optional<ppm_event_code> best;
	for(auto c : libsinsp::events::names_to_event_set({name})) {
		if(!best || std::make_pair(rank(c), c) > std::make_pair(rank(*best), *best)) {
			best = c;
		}
	}
	return best;
}

class test_engine {
public:
	explicit test_engine(const std::vector<plugin_spec>& plugins) {
		for(const auto& p : plugins) {
			auto plugin = m_inspector.register_plugin(p.library_path);
			std::string err;
			if(!plugin->init(p.init_config, err)) {
				throw std::runtime_error("plugin " + plugin->name() + " init failed: " + err);
			}
		}
		m_checks = std::make_unique<fixture_check_list>(m_ctx, m_inspector);
		m_source_idx = m_engine.add_source(
		        falco_common::syscall_source,
		        std::make_shared<sinsp_filter_factory>(&m_inspector, *m_checks),
		        std::make_shared<sinsp_evt_formatter_factory>(&m_inspector, *m_checks));
	}

	json versions() const {
		json plugins = json::object();
		for(const auto& p : m_inspector.get_plugin_manager()->plugins()) {
			plugins[p->name()] = p->plugin_version().as_string();
		}
		return {{"falco", FALCO_VERSION},
		        {"engine", falco_engine::engine_version().as_string()},
		        {"libs", FALCOSECURITY_LIBS_VERSION},
		        {"plugins", plugins}};
	}

	// Loads in order and stops at the first failing file, as Falco's load_rules_files does.
	json load_rules(const std::vector<std::string>& files) {
		std::vector<std::string> contents;
		falco::load_result::rules_contents_t rc;
		contents.reserve(files.size());
		for(const auto& f : files) {
			rc.emplace(f, contents.emplace_back(read_file(f)));
		}
		json results = json::array();
		bool successful = true;
		for(size_t i = 0; i < files.size() && successful; i++) {
			auto res = m_engine.load_rules(contents[i], files[i]);
			results.push_back(res->as_json(rc));
			successful = res->successful();
		}
		if(successful) {
			m_engine.complete_rule_loading();
		}
		return {{"successful", successful}, {"results", results}};
	}

	json plugin_requirements() const {
		std::vector<falco_engine::plugin_version_requirement> reqs;
		for(const auto& p : m_inspector.get_plugin_manager()->plugins()) {
			reqs.push_back({p->name(), p->plugin_version().as_string()});
		}
		std::string err;
		bool ok = m_engine.check_plugin_requirements(reqs, err);
		return {{"ok", ok}, {"error", err}};
	}

	json describe() const {
		return m_engine.describe_rule(nullptr, m_inspector.get_plugin_manager()->plugins());
	}

	json rules() {
		json out = json::array();
		for(const auto& r : m_engine.get_rules()) {
			auto info = m_engine.get_rule_collector()->rules().at(r.name);
			std::vector<const libsinsp::filter::ast::expr*> checks;
			auto compiled = ast_to_json(r.condition.get(), &checks);
			out.push_back({{"name", r.name},
			               {"source", r.source},
			               {"enabled", info->enabled},
			               {"priority", priority_name(r.priority)},
			               {"evttypes",
			                sorted(libsinsp::events::event_set_to_names(
			                        libsinsp::filter::ast::ppm_event_codes(r.condition.get())))},
			               {"condition_raw_ast", raw_ast(info->cond)},
			               {"condition_ast", compiled},
			               {"leaf_count", checks.size()}});
		}
		return out;
	}

	json run_case(const test_case& c) {
		json out = {{"id", c.id},
		            {"error", nullptr},
		            {"unknown_fields", json::array()},
		            {"matched_rules", json::array()},
		            {"traces", json::object()}};
		ppm_event_code code;
		try {
			code = validate(c, out["unknown_fields"]);
		} catch(const std::exception& e) {
			out["error"] = e.what();
			return out;
		}

		std::vector<uint8_t> raw(sizeof(scap_evt), 0);
		auto* hdr = reinterpret_cast<scap_evt*>(raw.data());
		hdr->len = sizeof(scap_evt);
		hdr->type = code;
		sinsp_evt evt(&m_inspector);
		evt.init_from_raw(raw.data(), 0);
		evt.set_source_idx(0);
		evt.set_source_name(sinsp_syscall_event_source_name);

		m_ctx.fields = &c.fields;
		try {
			out["matched_rules"] = matched_rules(evt);
			for(const auto& name : c.trace_rules) {
				out["traces"][name] = trace(name, evt);
			}
		} catch(const std::exception& e) {
			out["error"] = e.what();
			out["matched_rules"] = json::array();
			out["traces"] = json::object();
		}
		m_ctx.fields = nullptr;
		return out;
	}

private:
	ppm_event_code validate(const test_case& c, json& unknown_fields) {
		if(c.source != falco_common::syscall_source) {
			throw std::runtime_error("unsupported source '" + c.source + "'");
		}
		for(const auto& [name, values] : c.fields) {
			std::unique_ptr<sinsp_filter_check> chk;
			try {
				chk = m_checks->new_filter_check_from_fldname(name, &m_inspector, true);
			} catch(const sinsp_exception&) {
			}
			if(chk == nullptr) {
				unknown_fields.push_back(name);
				continue;
			}
			chk->parse_field_name(name, true, true);
			for(const auto& v : values) {
				try {
					encode_value(chk->get_field_info()->m_type, v);
				} catch(const sinsp_exception& e) {
					throw std::runtime_error("invalid value '" + v + "' for field " + name + ": " +
					                         e.what());
				}
			}
		}
		if(!unknown_fields.empty()) {
			throw std::runtime_error("unknown fields: " + unknown_fields.dump());
		}
		for(const auto& name : c.trace_rules) {
			if(m_engine.get_rules().at(name) == nullptr) {
				throw std::runtime_error("unknown rule in trace_rules: " + name);
			}
		}
		auto evt_type = c.fields.find("evt.type");
		if(evt_type == c.fields.end() || evt_type->second.size() != 1) {
			throw std::runtime_error("evt.type must have exactly one value");
		}
		auto code = event_code(evt_type->second[0]);
		if(!code) {
			throw std::runtime_error("unknown event type '" + evt_type->second[0] + "'");
		}
		return *code;
	}

	json matched_rules(sinsp_evt& evt) {
		json out = json::array();
		auto matches = m_engine.process_event(m_source_idx, &evt, falco_common::rule_matching::ALL);
		if(matches == nullptr) {
			return out;
		}
		for(const auto& m : *matches) {
			// the message part of falco_formats::format_event: '*' prints <NA> for missing fields
			auto format = m.format[0] == '*' ? m.format : "*" + m.format;
			std::string output;
			m_engine.create_formatter(m.source, format)->tostring(&evt, output);
			out.push_back({{"name", m.rule},
			               {"priority", priority_name(m.priority_num)},
			               {"output", output}});
		}
		return out;
	}

	json trace(const std::string& name, sinsp_evt& evt) {
		const auto* rule = m_engine.get_rules().at(name);
		m_ctx.missing.clear();
		bool result = rule->filter->run(&evt);
		json leaves = json::array();
		for(const auto& leaf : leaf_filters(*rule)) {
			leaves.push_back(leaf->run(&evt));
		}
		return {{"result", result}, {"leaves", leaves}, {"missing_fields", m_ctx.missing}};
	}

	// One filter per check of the compiled condition, in the AST JSON's id order.
	const std::vector<std::unique_ptr<sinsp_filter>>& leaf_filters(const falco_rule& rule) {
		auto& leaves = m_leaves[rule.name];
		if(leaves.empty()) {
			std::vector<const libsinsp::filter::ast::expr*> checks;
			ast_to_json(rule.condition.get(), &checks);
			auto factory = m_engine.filter_factory_for_source(m_source_idx);
			for(const auto* check : checks) {
				leaves.push_back(sinsp_filter_compiler(factory, check).compile());
			}
		}
		return leaves;
	}

	sinsp m_inspector;
	fixture_context m_ctx;
	std::unique_ptr<fixture_check_list> m_checks;
	falco_engine m_engine;
	std::size_t m_source_idx = 0;
	std::map<std::string, std::vector<std::unique_ptr<sinsp_filter>>> m_leaves;
};

static json run_job(const job& j) {
	test_engine engine(j.plugins);
	json result = {{"versions", engine.versions()},
	               {"load", engine.load_rules(j.rules_files)},
	               {"plugin_requirements", engine.plugin_requirements()},
	               {"rules", json::array()},
	               {"cases", json::array()}};
	if(!result["load"]["successful"].get<bool>()) {
		return result;
	}
	if(j.describe) {
		result["describe"] = engine.describe();
	}
	result["rules"] = engine.rules();
	for(const auto& c : j.cases) {
		result["cases"].push_back(engine.run_case(c));
	}
	return result;
}

int main(int argc, char** argv) {
	json result;
	try {
		std::string text;
		if(argc == 3 && std::string(argv[1]) == "--job") {
			text = read_file(argv[2]);
		} else if(argc == 1) {
			std::stringstream ss;
			ss << std::cin.rdbuf();
			text = ss.str();
		} else {
			throw std::runtime_error("usage: falco-test-engine [--job job.json]");
		}
		result = run_job(parse_job(json::parse(text)));
	} catch(const std::exception& e) {
		std::cout << json{{"fatal", e.what()}}.dump(-1, ' ', false, json::error_handler_t::replace)
		          << std::endl;
		return 2;
	}
	std::cout << result.dump(-1, ' ', false, json::error_handler_t::replace) << std::endl;
	return 0;
}
