//! [`Metered`] answers as [`PostgreSqlDialect`] does and counts the question.
//! A method Postgres's dialect overrides must be here, or the trait's default
//! would answer instead; check the list when sqlparser is bumped. The rest
//! are here to be counted: the parser asks one of them in every expression,
//! data type, query, `SELECT` and table it starts.

use std::any::TypeId;

use sqlparser::ast::DataType;
use sqlparser::ast::{Expr, Statement};
use sqlparser::dialect::{BindPlaceholderStyle, Dialect, PostgreSqlDialect, Precedence};
use sqlparser::keywords::Keyword;
use sqlparser::parser::{Parser, ParserError};

use super::budget::Metered;

macro_rules! as_postgres {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {
        $(fn $name(&self, $($arg: $ty),*) -> $out {
            self.step();
            self.postgres.$name($($arg),*)
        })*
    };
}

/// The same, where the parser's place is known.
macro_rules! as_postgres_at {
    ($(fn $name:ident($parser:ident: $at:ty $(, $arg:ident: $ty:ty)*) -> $out:ty;)*) => {
        $(fn $name(&self, $parser: $at $(, $arg: $ty)*) -> $out {
            self.step_at($parser);
            self.postgres.$name($parser $(, $arg)*)
        })*
    };
}

impl Dialect for Metered {
    /// The parser's checks for a particular dialect see Postgres's.
    fn dialect(&self) -> TypeId {
        self.step();
        TypeId::of::<PostgreSqlDialect>()
    }

    as_postgres_at! {
        fn parse_prefix(parser: &mut Parser) -> Option<Result<Expr, ParserError>>;
        fn parse_infix(parser: &mut Parser, expr: &Expr, precedence: u8) -> Option<Result<Expr, ParserError>>;
        fn parse_statement(parser: &mut Parser) -> Option<Result<Statement, ParserError>>;
        fn parse_data_type(parser: &mut Parser) -> Option<Result<DataType, ParserError>>;
        fn get_next_precedence(parser: &Parser) -> Option<Result<u8, ParserError>>;
    }

    // Not overridden by Postgres's dialect: counted only.
    as_postgres! {
        fn prec_unknown() -> u8;
        fn supports_from_first_select() -> bool;
        fn supports_top_before_distinct() -> bool;
        fn is_column_alias(kw: &Keyword, parser: &mut Parser) -> bool;
        fn is_select_item_alias(explicit: bool, kw: &Keyword, parser: &mut Parser) -> bool;
        fn is_table_factor(kw: &Keyword, parser: &mut Parser) -> bool;
        fn is_table_factor_alias(explicit: bool, kw: &Keyword, parser: &mut Parser) -> bool;
    }

    // Overridden by Postgres's dialect.
    as_postgres! {
        fn prec_value(prec: Precedence) -> u8;
        fn identifier_quote_style(identifier: &str) -> Option<char>;
        fn ordered_bind_placeholder_style() -> Option<BindPlaceholderStyle>;
        fn is_delimited_identifier_start(ch: char) -> bool;
        fn is_identifier_start(ch: char) -> bool;
        fn is_identifier_part(ch: char) -> bool;
        fn is_custom_operator_part(ch: char) -> bool;
        fn is_reserved_for_identifier(kw: Keyword) -> bool;
        fn is_table_alias(kw: &Keyword, parser: &mut Parser) -> bool;
        fn is_interval_qualifier(kw: Keyword) -> bool;
        fn is_custom_type_typed_string(first_keyword: Keyword, qualified: bool) -> bool;
        fn allow_extract_custom() -> bool;
        fn allow_extract_single_quotes() -> bool;
        fn supports_cte_materialization() -> bool;
        fn supports_unicode_string_literal() -> bool;
        fn supports_filter_during_aggregation() -> bool;
        fn supports_group_by_expr() -> bool;
        fn supports_drop_group() -> bool;
        fn supports_alter_user_as_alter_role() -> bool;
        fn supports_create_group() -> bool;
        fn supports_create_role_if_not_exists() -> bool;
        fn supports_create_index_with_clause() -> bool;
        fn supports_sql_option_without_value() -> bool;
        fn supports_explain_with_utility_options() -> bool;
        fn supports_listen_notify() -> bool;
        fn supports_exclude_constraint() -> bool;
        fn supports_factorial_operator() -> bool;
        fn supports_bitwise_shift_operators() -> bool;
        fn supports_tilde_like_match_operator() -> bool;
        fn supports_comparison_in_between_low_bound() -> bool;
        fn supports_comment_on() -> bool;
        fn supports_load_extension() -> bool;
        fn supports_named_fn_args_with_colon_operator() -> bool;
        fn supports_named_fn_args_with_expr_name() -> bool;
        fn supports_named_fn_args_with_assignment_operator() -> bool;
        fn supports_empty_projections() -> bool;
        fn supports_nested_comments() -> bool;
        fn supports_copy_from_stdin_data() -> bool;
        fn supports_string_escape_constant() -> bool;
        fn supports_numeric_literal_underscores() -> bool;
        fn supports_non_decimal_integer_literals() -> bool;
        fn supports_array_typedef_with_brackets() -> bool;
        fn supports_geometric_types() -> bool;
        fn supports_order_by_using_operator() -> bool;
        fn supports_set_names() -> bool;
        fn supports_alter_column_type_using() -> bool;
        fn supports_left_associative_joins_without_parens() -> bool;
        fn supports_notnull_operator() -> bool;
        fn supports_interval_options() -> bool;
        fn supports_insert_table_alias() -> bool;
        fn supports_create_table_like_parenthesized() -> bool;
        fn supports_select_wildcard_with_alias() -> bool;
        fn supports_comma_separated_trim() -> bool;
        fn supports_xml_expressions() -> bool;
        fn supports_aliased_function_args() -> bool;
        fn supports_comment_optimizer_hint() -> bool;
        fn supports_add_column_if_not_exists() -> bool;
        fn supports_attach_partition_of() -> bool;
        fn supports_detach_partition_of() -> bool;
        fn supports_table_inheritance_markers() -> bool;
        fn supports_column_generic_options() -> bool;
        fn supports_string_literal_column_alias(explicit: bool) -> bool;
        fn supports_string_literal_table_alias(explicit: bool) -> bool;
    }
}
