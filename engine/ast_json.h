#pragma once

#include <libsinsp/filter/ast.h>

#include <nlohmann/json.hpp>

#include <vector>

// Serializes a filter AST per the AST table in docs/engine-protocol.md. When checks is non-null,
// check nodes get depth-first ids and are appended to checks in id order.
nlohmann::json ast_to_json(const libsinsp::filter::ast::expr* e,
                           std::vector<const libsinsp::filter::ast::expr*>* checks = nullptr);
