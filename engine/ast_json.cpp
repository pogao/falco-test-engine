#include "ast_json.h"

using namespace libsinsp::filter::ast;
using nlohmann::json;

namespace {

class ast_json_visitor : public const_expr_visitor {
public:
	explicit ast_json_visitor(std::vector<const expr*>* checks): m_checks(checks) {}

	json convert(const expr* e) {
		e->accept(this);
		return std::move(m_last);
	}

	void visit(const and_expr* e) override { m_last = logical("and", e->children); }

	void visit(const or_expr* e) override { m_last = logical("or", e->children); }

	void visit(const not_expr* e) override {
		m_last = {{"type", "not"}, {"child", convert(e->child.get())}};
	}

	void visit(const identifier_expr* e) override {
		m_last = {{"type", "identifier"}, {"name", e->identifier}};
	}

	void visit(const value_expr* e) override {
		m_last = {{"type", "value"}, {"value", e->value}};
	}

	void visit(const list_expr* e) override {
		m_last = {{"type", "list"}, {"values", e->values}};
	}

	void visit(const transformer_list_expr* e) override {
		m_last = logical("transformer_list", e->children);
	}

	void visit(const unary_check_expr* e) override {
		json out = check(e, e->op);
		out["lhs"] = convert(e->left.get());
		m_last = std::move(out);
	}

	void visit(const binary_check_expr* e) override {
		json out = check(e, e->op);
		out["lhs"] = convert(e->left.get());
		out["rhs"] = convert(e->right.get());
		m_last = std::move(out);
	}

	void visit(const field_expr* e) override {
		m_last = {{"type", "field"}, {"field", e->field}, {"arg", optional(e->arg)}};
	}

	void visit(const field_transformer_expr* e) override {
		json args = json::array();
		for(const auto& v : e->values) {
			args.push_back(convert(v.get()));
		}
		m_last = {{"type", "transformer"},
		          {"name", e->transformer},
		          {"args", std::move(args)},
		          {"arg", optional(e->arg)}};
	}

private:
	json logical(const char* type, const std::vector<std::unique_ptr<expr>>& children) {
		json out = json::array();
		for(const auto& c : children) {
			out.push_back(convert(c.get()));
		}
		return {{"type", type}, {"children", std::move(out)}};
	}

	json check(const expr* e, const std::string& op) {
		json out = {{"type", "check"}, {"op", op}};
		if(m_checks != nullptr) {
			out["id"] = m_checks->size();
			m_checks->push_back(e);
		}
		return out;
	}

	static json optional(const std::optional<std::string>& s) {
		return s ? json(*s) : json(nullptr);
	}

	std::vector<const expr*>* m_checks;
	json m_last;
};

}  // namespace

json ast_to_json(const expr* e, std::vector<const expr*>* checks) {
	return ast_json_visitor(checks).convert(e);
}
