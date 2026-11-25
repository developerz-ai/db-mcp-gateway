//! Statements that reach several limits at once, each inside the one before:
//! joins nested to the bound, expressions nested to the parser's own limit, a
//! chain of unions to the SELECT bound, parentheses to their bound, and a
//! chain of operators over the rest of the length.

use super::*;

/// `(opening, closing)` of one level of nesting.
const NESTS: &[(&str, &str)] = &[
    ("f(", ")"),
    ("ARRAY[", "]"),
    ("NOT ", ""),
    ("CASE WHEN ", " THEN a END"),
    ("EXISTS(SELECT ", ")"),
    ("(SELECT * FROM t JOIN f(", ") ON a)"),
];

/// Operators the parser chains in a loop, one tree level each.
const LINKS: &[&str] = &["+a", "||a", "::a", "=a"];

/// The innermost structure, inside the joins and the nested expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Core {
    /// The operator chain alone, over all the length there is.
    Chain,
    /// The operator chain in the first SELECT of a chain of unions, over
    /// nested column definitions: every bound at once.
    Everything,
}

/// A balanced statement in three parts, so a test can end it early.
#[derive(Debug)]
struct Statement {
    before_chain: String,
    link: &'static str,
    after_chain: String,
}

impl Statement {
    /// [`MAX_JOINS`] joins around `depth` levels of `nest` around `core`.
    fn new(nest: (&str, &str), depth: usize, link: &'static str, core: Core) -> Self {
        let (opening, closing) = nest;
        let opened = opening.repeat(depth);
        let outer_joins = MAX_JOINS - 1 - opened.matches(" JOIN ").count();
        let mut before_chain = format!("{} JOIN f({opened}", joins(outer_joins));
        let mut after_chain = String::new();
        if core == Core::Everything {
            before_chain.push_str("EXISTS(SELECT ");
            let table = " FROM JSON_TABLE(a,'$' COLUMNS(";
            let levels = MAX_PARENS - most_open(&format!("{before_chain}{table}"));
            after_chain = format!(
                "{table}{}b FOR ORDINALITY{}{})",
                "NESTED '' COLUMNS(".repeat(levels),
                ")".repeat(levels + 2),
                " UNION SELECT 1".repeat(MAX_SELECTS - before_chain.matches("SELECT ").count()),
            );
        }
        before_chain.push('a');
        after_chain.push_str(&closing.repeat(depth));
        after_chain.push(')');
        Self {
            before_chain,
            link,
            after_chain,
        }
    }

    fn links(&self, bytes: usize) -> String {
        let room = bytes - self.before_chain.len() - self.after_chain.len();
        self.link.repeat(room / self.link.len())
    }

    /// The complete statement, the chain filling it to exactly `bytes`.
    fn complete(&self, bytes: usize) -> String {
        let Self {
            before_chain,
            after_chain,
            ..
        } = self;
        let mut sql = format!("{before_chain}{}{after_chain}", self.links(bytes));
        sql.push_str(&" ".repeat(bytes - sql.len()));
        sql
    }

    /// The complete statement with only one link.
    fn shortest(&self) -> String {
        self.complete(self.before_chain.len() + self.after_chain.len() + self.link.len())
    }

    /// Nothing closed, and two names in a row where the chain ends.
    fn cut_after_the_chain(&self, bytes: usize) -> String {
        format!("{}{} b c", self.before_chain, self.links(bytes))
    }
}

/// The most parentheses open at once. The statements here hold none in quotes.
fn most_open(sql: &str) -> usize {
    let (mut open, mut most) = (0usize, 0);
    for byte in sql.bytes() {
        match byte {
            b'(' => open += 1,
            b')' => open -= 1,
            _ => {}
        }
        most = most.max(open);
    }
    most
}

/// How deep the parser lets `nest` go inside the joins: one level more and it
/// refuses the text, which holds nothing else to refuse.
fn deepest(nest: (&str, &str), core: Core) -> usize {
    (1..)
        .find(
            |depth| match is_read_only(&Statement::new(nest, depth + 1, "+a", core).shortest()) {
                Ok(()) => false,
                Err(GuardError::Parse(_)) => true,
                Err(other) => panic!("{nest:?} x {}: {other}", depth + 1),
            },
        )
        .expect("the parser has a limit")
}

fn assert_answers(nest: (&str, &str), depth: usize, link: &'static str, core: Core) {
    let case = format!("{nest:?} x {depth}, {link:?}, {core:?}");
    let statement = Statement::new(nest, depth, link, core);

    let complete = statement.complete(MAX_SQL_BYTES);
    assert_eq!(complete.len(), MAX_SQL_BYTES, "{case}");
    assert_eq!(complete.matches(" JOIN ").count(), MAX_JOINS, "{case}");
    if core == Core::Everything {
        assert_eq!(complete.matches("SELECT ").count(), MAX_SELECTS, "{case}");
        assert_eq!(most_open(&complete), MAX_PARENS, "{case}");
    }
    let got = on_worker_stack(move || is_read_only(&complete));
    assert_eq!(got, Ok(()), "{case}");

    // Refused only at the last byte: the whole tree stands by then.
    let appended = format!("{})", statement.complete(MAX_SQL_BYTES - 1));
    let got = on_worker_stack(move || is_read_only(&appended));
    let at_the_end = SqlLocation {
        line: 1,
        column: MAX_SQL_BYTES as u64,
    };
    assert_eq!(got, Err(GuardError::Parse(Some(at_the_end))), "{case}");

    let cut = statement.cut_after_the_chain(MAX_SQL_BYTES - 4);
    let got = on_worker_stack(move || is_read_only(&cut));
    // Each level of some nests reads the whole chain again.
    let refused = matches!(
        got,
        Err(GuardError::Parse(_) | GuardError::TooMuchWork { .. })
    );
    assert!(refused, "{case}: {got:?}");
}

fn assert_every_nest_answers(core: Core) {
    for &nest in NESTS {
        let depth = deepest(nest, core);
        for link in LINKS {
            assert_answers(nest, depth, link, core);
        }
    }
}

#[test]
fn joins_nesting_and_length_at_their_limits_together_get_the_right_answer() {
    assert_every_nest_answers(Core::Chain);
}

#[test]
fn every_limit_reached_together_gets_the_right_answer() {
    assert_every_nest_answers(Core::Everything);
}
