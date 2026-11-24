use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Visiting,
    Done,
}

/// Returns the first cycle found, with the starting node repeated at the end.
pub(crate) fn find_cycle(edges: &BTreeMap<String, Vec<String>>) -> Option<Vec<String>> {
    let mut marks: HashMap<&str, Mark> = HashMap::new();
    let mut stack: Vec<&str> = Vec::new();
    for node in edges.keys() {
        if let Some(cycle) = visit(node, edges, &mut marks, &mut stack) {
            return Some(cycle);
        }
    }
    None
}

fn visit<'a>(
    node: &'a str,
    edges: &'a BTreeMap<String, Vec<String>>,
    marks: &mut HashMap<&'a str, Mark>,
    stack: &mut Vec<&'a str>,
) -> Option<Vec<String>> {
    match marks.get(node) {
        Some(Mark::Done) => return None,
        Some(Mark::Visiting) => {
            let start = stack.iter().position(|n| *n == node).unwrap_or(0);
            let mut cycle: Vec<String> = stack[start..].iter().map(|n| n.to_string()).collect();
            cycle.push(node.to_string());
            return Some(cycle);
        }
        None => {}
    }
    marks.insert(node, Mark::Visiting);
    stack.push(node);
    if let Some(next) = edges.get(node) {
        for target in next {
            if let Some(cycle) = visit(target.as_str(), edges, marks, stack) {
                return Some(cycle);
            }
        }
    }
    stack.pop();
    marks.insert(node, Mark::Done);
    None
}

/// Transitive closure from `start`, including `start` itself.
pub(crate) fn reachable(start: &str, edges: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start.to_string()];
    while let Some(node) = stack.pop() {
        if !seen.insert(node.clone()) {
            continue;
        }
        if let Some(next) = edges.get(&node) {
            stack.extend(next.iter().filter(|n| !seen.contains(*n)).cloned());
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edges(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<String>> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (from, to) in pairs {
            map.entry(from.to_string()).or_default().push(to.to_string());
            map.entry(to.to_string()).or_default();
        }
        map
    }

    #[test]
    fn detects_cycle() {
        let cycle = find_cycle(&edges(&[("a", "b"), ("b", "c"), ("c", "a")])).expect("ciclo");
        assert_eq!(cycle.first(), cycle.last());
        assert_eq!(cycle.len(), 4);
    }

    #[test]
    fn dag_has_no_cycle() {
        assert!(find_cycle(&edges(&[("a", "b"), ("a", "c"), ("b", "c")])).is_none());
    }

    #[test]
    fn reachable_includes_start_and_transitive_nodes() {
        let set = reachable("a", &edges(&[("a", "b"), ("b", "c"), ("d", "a")]));
        assert_eq!(set.into_iter().collect::<Vec<_>>(), ["a", "b", "c"]);
    }
}
