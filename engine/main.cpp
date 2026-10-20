#include <falco_engine.h>
#include <falco_engine_version.h>
#include <iostream>

int main() {
	auto engine = std::make_shared<falco_engine>();
	sinsp inspector;
	sinsp_filter_check_list checks;
	engine->add_source("syscall",
	                   std::make_shared<sinsp_filter_factory>(&inspector, checks),
	                   std::make_shared<sinsp_evt_formatter_factory>(&inspector, checks));
	auto res = engine->load_rules("- rule: t\n  desc: t\n  condition: evt.type=execve and proc.name=bash\n  output: x\n  priority: WARNING\n", "t.yaml");
	std::cout << falco_engine::engine_version().as_string() << " " << res->successful() << std::endl;
}
