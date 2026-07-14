//! XML canonicalization per W3C XML-C14N (TR/2001/REC-xml-c14n-20010315) and
//! Exclusive C14N (TR/2002/REC-xml-exc-c14n-20020718).
//!
//! See `docs/rfcs/RFC-002-xml-crypto-core.md` §2.
//!
//! Implementation notes
//! --------------------
//! Canonicalization is a pure function of the parsed `Document` tree — no
//! source-byte slicing, no re-parse. Both algorithms walk the element subtree
//! in document order, threading an explicit ancestor stack so that:
//!
//! - the *in-scope* namespace declarations at each element can be reconstructed
//!   from `namespaces_declared_here` along the chain;
//! - the *rendered* namespace declarations (what we emit on the canonical
//!   element) can be tracked separately so descendants do not redundantly
//!   re-emit a binding already output on an ancestor in the canonical form.
//!
//! The two algorithms differ only in how the *apex* element's rendered set is
//! computed:
//!
//! - **Exclusive**: only namespaces "visibly utilized" by the element or its
//!   descendants (subject to the same in-output-ancestor check) — plus any
//!   prefixes named by `<ec:InclusiveNamespaces PrefixList="…">`.
//! - **Inclusive**: every in-scope namespace declaration on the apex (including
//!   ancestor declarations that the apex's own subtree does not visibly use).
//!
//! Comments are preserved only for the `WithComments` variants.

use crate::dsig::algorithms::C14nAlgorithm;
use crate::error::Error;
use crate::xml::parse::{Document, Element, Node, QName};

/// XML namespace URI implicitly bound to the `xml` prefix at all times.
/// Never re-rendered (per both C14N specs).
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Canonicalize an element subtree per the chosen algorithm.
///
/// `inclusive_namespace_prefixes` is honored only for the two Exclusive variants
/// — these are the prefixes from `<ec:InclusiveNamespaces PrefixList="…">` that
/// the spec requires Exclusive C14N to inherit from the ancestor in-scope
/// namespace set even when the element itself doesn't visibly use them.
/// For the Inclusive variants the parameter is ignored.
///
/// `ancestor_chain` is the document-order chain from the document root down
/// to (but not including) `element`. The C14N algorithms need ancestor
/// in-scope namespace declarations to compute the "rendered" namespaces.
///
/// `document` is reserved for future expansion (e.g. entity resolution) — for
/// v0.1 it is unused.
pub(crate) fn canonicalize(
    _document: &Document,
    element: &Element,
    ancestor_chain: &[&Element],
    algorithm: C14nAlgorithm,
    inclusive_namespace_prefixes: &[&str],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    // The "rendered" namespace stack carries (prefix, URI) bindings that have
    // already been emitted on an output ancestor of the current element. The
    // apex element starts with an empty rendered set — even for Inclusive C14N,
    // because ancestor declarations are only candidates for *rendering on the
    // apex*, they have not actually been written to the output yet.
    let rendered: Vec<(Option<String>, String)> = Vec::new();
    emit_element(
        element,
        ancestor_chain,
        &rendered,
        /* is_apex */ true,
        algorithm,
        inclusive_namespace_prefixes,
        &mut out,
    )?;
    Ok(out)
}

// =============================================================================
// Element emission
// =============================================================================

fn emit_element(
    element: &Element,
    ancestor_chain: &[&Element],
    rendered_above: &[(Option<String>, String)],
    is_apex: bool,
    algorithm: C14nAlgorithm,
    inclusive_namespace_prefixes: &[&str],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    // Compute the namespace declarations to render on this element.
    let to_render = compute_rendered_namespaces(
        element,
        ancestor_chain,
        rendered_above,
        is_apex,
        algorithm,
        inclusive_namespace_prefixes,
    )?;

    // Element prefix: walk in-scope decls (ancestors + own) to find the prefix
    // bound to the element's namespace URI. The parser preserves the literal
    // source prefix on `Element::source_prefix`; when two in-scope prefixes
    // resolve to the same URI (e.g. Keycloak's `<saml:Assertion xmlns="…"
    // xmlns:saml="…">`), we prefer the prefix the signer wrote, because c14n
    // must reproduce the bytes that the signature was computed against.
    let elem_prefix = lookup_prefix_for_uri(
        element.qname().namespace(),
        ancestor_chain,
        element,
        /* is_attribute */ false,
        element.source_prefix.as_deref(),
    )?;

    // ---- start tag ----------------------------------------------------------
    out.push(b'<');
    push_qname(out, elem_prefix.as_deref(), element.qname().local());

    // Namespace declarations, sorted: default (no prefix) first, then by prefix
    // lexicographically (byte-wise).
    let mut ns_sorted = to_render;
    ns_sorted.sort_by(|a, b| ns_sort_key(a).cmp(&ns_sort_key(b)));
    for (prefix, uri) in &ns_sorted {
        out.push(b' ');
        match prefix {
            None => out.extend_from_slice(b"xmlns"),
            Some(p) => {
                out.extend_from_slice(b"xmlns:");
                out.extend_from_slice(p.as_bytes());
            }
        }
        out.extend_from_slice(b"=\"");
        push_attr_value_escaped(out, uri);
        out.push(b'"');
    }

    // Attributes, sorted lexicographically by (namespace URI, local name).
    // Unqualified attributes have URI "" and sort first. Each attribute
    // carries its own source-prefix hint (see `Element::source_prefix` for
    // why) so the canonical output preserves the signer's prefix choice.
    let mut attrs_sorted: Vec<(&QName, Option<&str>, &str)> =
        element.attributes_with_source_prefix().collect();
    attrs_sorted.sort_by(|(a, _, _), (b, _, _)| attr_sort_key(a).cmp(&attr_sort_key(b)));
    for (qname, source_prefix, value) in &attrs_sorted {
        out.push(b' ');
        let attr_prefix = lookup_prefix_for_uri(
            qname.namespace(),
            ancestor_chain,
            element,
            /* is_attribute */ true,
            *source_prefix,
        )?;
        push_qname(out, attr_prefix.as_deref(), qname.local());
        out.extend_from_slice(b"=\"");
        push_attr_value_escaped(out, value);
        out.push(b'"');
    }

    out.push(b'>');

    // ---- children -----------------------------------------------------------
    // Build the rendered-above set for children: it is `rendered_above`
    // overlaid with `ns_sorted` (later same-prefix entries shadow earlier).
    let mut rendered_for_children: Vec<(Option<String>, String)> =
        Vec::with_capacity(rendered_above.len().saturating_add(ns_sorted.len()));
    rendered_for_children.extend_from_slice(rendered_above);
    for (prefix, uri) in ns_sorted {
        merge_rendered(&mut rendered_for_children, prefix, uri);
    }

    let mut child_chain: Vec<&Element> = ancestor_chain.to_vec();
    child_chain.push(element);

    for child in element.children() {
        match child {
            Node::Element(child_elem) => {
                emit_element(
                    child_elem,
                    &child_chain,
                    &rendered_for_children,
                    /* is_apex */ false,
                    algorithm,
                    inclusive_namespace_prefixes,
                    out,
                )?;
            }
            Node::Text(text) => {
                push_text_escaped(out, text);
            }
            Node::Comment(content) => {
                if algorithm.includes_comments() {
                    out.extend_from_slice(b"<!--");
                    out.extend_from_slice(content.as_bytes());
                    out.extend_from_slice(b"-->");
                }
            }
        }
    }

    // ---- end tag ------------------------------------------------------------
    out.extend_from_slice(b"</");
    push_qname(out, elem_prefix.as_deref(), element.qname().local());
    out.push(b'>');

    Ok(())
}

// =============================================================================
// Namespace rendering computation
// =============================================================================

/// Compute the (prefix, URI) namespace declarations to render on `element`.
///
/// For Exclusive C14N (RFC 3741 §2): a binding is rendered iff
///   (a) it is *visibly utilized* by `element` (prefix appears on the element's
///       own QName or on one of its attribute QNames), OR
///   (a') the prefix is in `inclusive_namespace_prefixes` AND that prefix is
///        currently in scope at `element`, AND
///   (b) the same (prefix, URI) is not already in scope from an output
///       ancestor in the canonical output (`rendered_above`).
///
/// Special handling for the default namespace: if the element is unprefixed,
/// the default namespace is "visibly utilized". If the parent output context
/// had a non-empty default ns and this element's in-scope default is empty,
/// `xmlns=""` is rendered to explicitly cancel it.
///
/// For Inclusive C14N (XML-C14N §2) on the *apex*: every in-scope binding
/// (excluding the `xml` prefix) is a candidate; the `rendered_above` filter
/// still applies (but for the apex `rendered_above` is empty, so all in-scope
/// bindings render). For *descendants*, Inclusive C14N renders only what the
/// element introduces or overrides relative to `rendered_above` — i.e., every
/// binding whose (prefix, URI) is not already in `rendered_above`.
fn compute_rendered_namespaces(
    element: &Element,
    ancestor_chain: &[&Element],
    rendered_above: &[(Option<String>, String)],
    is_apex: bool,
    algorithm: C14nAlgorithm,
    inclusive_namespace_prefixes: &[&str],
) -> Result<Vec<(Option<String>, String)>, Error> {
    let in_scope = namespaces_in_scope(element, ancestor_chain);

    if algorithm.is_exclusive() {
        compute_exclusive(
            element,
            &in_scope,
            rendered_above,
            inclusive_namespace_prefixes,
        )
    } else {
        Ok(compute_inclusive(
            element,
            &in_scope,
            rendered_above,
            is_apex,
        ))
    }
}

fn compute_exclusive(
    element: &Element,
    in_scope: &[(Option<String>, String)],
    rendered_above: &[(Option<String>, String)],
    inclusive_namespace_prefixes: &[&str],
) -> Result<Vec<(Option<String>, String)>, Error> {
    let mut out: Vec<(Option<String>, String)> = Vec::new();

    // Prefixes visibly utilized by the element's own QName and its
    // namespace-qualified attribute QNames.
    let utilized = utilized_prefixes(element, in_scope)?;

    // (1) Visibly utilized bindings.
    for prefix in &utilized {
        let uri = lookup_in_scope(in_scope, prefix.as_deref());
        let uri = match uri {
            Some(u) => u.to_owned(),
            None => {
                // The default namespace is "in scope" with URI "" when not
                // declared. If we're rendering the default ns for an
                // unprefixed element with no default ns in scope, the binding
                // is xmlns="" and only renders if the output ancestor had
                // a non-empty default ns (i.e., we need to clear it).
                if prefix.is_none() {
                    String::new()
                } else {
                    return Err(Error::XmlEmit(format!(
                        "namespace prefix '{}' visibly utilized but not in scope",
                        prefix.as_deref().unwrap_or("")
                    )));
                }
            }
        };

        if should_render(prefix.as_deref(), &uri, rendered_above) {
            push_unique(&mut out, prefix.clone(), uri);
        }
    }

    // (2) InclusiveNamespaces PrefixList: each named prefix gets rendered if
    // it's currently in scope and not already in the output ancestor.
    for &pfx_str in inclusive_namespace_prefixes {
        // The token "#default" in a PrefixList refers to the default namespace.
        // Per Exclusive C14N §2: "If the PrefixList token is `#default`, then
        // the default namespace is added to the InclusiveNamespaces set."
        let prefix: Option<String> = if pfx_str == "#default" {
            None
        } else {
            Some(pfx_str.to_owned())
        };
        let uri = match lookup_in_scope(in_scope, prefix.as_deref()) {
            Some(u) => u.to_owned(),
            None => {
                if prefix.is_none() {
                    String::new()
                } else {
                    // Prefix named in PrefixList but not in scope — skip silently.
                    // (The spec says PrefixList prefixes that aren't in scope are
                    // simply not rendered.)
                    continue;
                }
            }
        };
        if should_render(prefix.as_deref(), &uri, rendered_above) {
            push_unique(&mut out, prefix, uri);
        }
    }

    Ok(out)
}

fn compute_inclusive(
    element: &Element,
    in_scope: &[(Option<String>, String)],
    rendered_above: &[(Option<String>, String)],
    is_apex: bool,
) -> Vec<(Option<String>, String)> {
    let mut out: Vec<(Option<String>, String)> = Vec::new();

    if is_apex {
        // The apex element renders every in-scope namespace declaration that
        // is not already in the output ancestor set (which is empty for the
        // apex), except the implicit `xml` binding.
        for (prefix, uri) in in_scope {
            // Skip the implicit xml binding.
            if prefix.as_deref() == Some("xml") && uri == XML_NS {
                continue;
            }
            // Skip `xmlns=""` on the apex unless there's something to cancel
            // (the apex has no rendered_above, so empty default ns just means
            // "no default" and we skip emitting it).
            if prefix.is_none() && uri.is_empty() {
                continue;
            }
            if should_render(prefix.as_deref(), uri, rendered_above) {
                push_unique(&mut out, prefix.clone(), uri.clone());
            }
        }
    } else {
        // Descendants in Inclusive C14N: render the bindings declared *on
        // this element* (its `namespaces_declared_here`) that aren't already
        // in the output-ancestor set.
        for (prefix, uri) in &element.namespaces_declared_here {
            if prefix.as_deref() == Some("xml") && uri == XML_NS {
                continue;
            }
            if should_render(prefix.as_deref(), uri, rendered_above) {
                push_unique(&mut out, prefix.clone(), uri.clone());
            }
        }
    }

    out
}

/// Collect the set of prefixes visibly utilized at `element` for Exclusive
/// C14N: the prefix of the element's own QName, and the prefix of each of its
/// namespace-qualified attributes. `None` represents the default namespace,
/// which is "visibly utilized" iff the element is unprefixed.
///
/// Each lookup honors the source-prefix hint recorded on the parsed value so
/// that — when multiple in-scope prefixes resolve to the same URI — the
/// "visibly utilized" prefix matches the one the signer actually wrote, and
/// the rendered declaration is the binding the signer rendered.
fn utilized_prefixes(
    element: &Element,
    in_scope: &[(Option<String>, String)],
) -> Result<Vec<Option<String>>, Error> {
    let mut out: Vec<Option<String>> = Vec::new();

    // Element name prefix.
    let elem_uri = element.qname().namespace();
    let elem_prefix = prefix_for_uri(
        in_scope,
        elem_uri,
        /* is_attribute */ false,
        element.source_prefix.as_deref(),
    )?;
    push_unique_opt(&mut out, elem_prefix);

    // Each attribute's prefix.
    for (qname, source_prefix, _value) in element.attributes_with_source_prefix() {
        // Unqualified attributes do NOT visibly utilize the default namespace
        // (XML Namespaces 1.0 §6.2 — attributes have no default).
        let Some(uri) = qname.namespace() else {
            continue;
        };
        // `xml:` prefix is always implicitly bound and not eligible to render.
        if uri == XML_NS {
            continue;
        }
        let pfx = prefix_for_uri(
            in_scope,
            Some(uri),
            /* is_attribute */ true,
            source_prefix,
        )?;
        // Attributes never use the default namespace; pfx must be Some.
        if pfx.is_some() {
            push_unique_opt(&mut out, pfx);
        }
    }

    Ok(out)
}

/// Return whether a (prefix, URI) binding needs to be rendered, given the set
/// of bindings already emitted on output ancestors.
fn should_render(
    prefix: Option<&str>,
    uri: &str,
    rendered_above: &[(Option<String>, String)],
) -> bool {
    // The xml: prefix is implicit and never rendered.
    if prefix == Some("xml") && uri == XML_NS {
        return false;
    }

    // Find the most recent rendered binding for this prefix.
    let prev = rendered_above
        .iter()
        .rev()
        .find(|(p, _)| p.as_deref() == prefix)
        .map(|(_, u)| u.as_str());

    match (prev, prefix, uri) {
        // No prior binding for this prefix in the output ancestor.
        (None, None, "") => false, // xmlns="" with no rendered default above: nothing to cancel.
        (None, _, _) => true,
        (Some(prev_uri), _, _) => prev_uri != uri,
    }
}

// =============================================================================
// Namespace scope and prefix lookup helpers
// =============================================================================

/// Build the in-scope namespace bindings for `element`, walking the ancestor
/// chain in document order, then this element's own declarations. Later
/// declarations for the same prefix shadow earlier ones.
///
/// The `xml` prefix is implicit and not included in this list — it is handled
/// specially at every use-site (prefix-for-URI lookup checks `XML_NS`
/// directly; rendering checks `should_render` which skips xml).
fn namespaces_in_scope(
    element: &Element,
    ancestor_chain: &[&Element],
) -> Vec<(Option<String>, String)> {
    let mut out: Vec<(Option<String>, String)> = Vec::new();
    for ancestor in ancestor_chain {
        for (prefix, uri) in &ancestor.namespaces_declared_here {
            merge_rendered(&mut out, prefix.clone(), uri.clone());
        }
    }
    for (prefix, uri) in &element.namespaces_declared_here {
        merge_rendered(&mut out, prefix.clone(), uri.clone());
    }
    out
}

/// Resolve a namespace URI to the prefix used to bind it in the in-scope set.
/// Returns `Ok(None)` for the default namespace.
///
/// For *attributes* in Exclusive C14N, only a non-default (named) prefix can
/// be used to qualify an attribute; unqualified attributes have no namespace.
/// If `uri` is not bound in scope, returns an error.
///
/// `source_prefix` is the prefix the source document used to write this
/// element/attribute (carried through from the parser on
/// `Element::source_prefix` / `Attribute::source_prefix`). When `Some`, c14n
/// prefers that prefix iff the in-scope binding for the URI matches — this
/// keeps the canonical bytes byte-identical to what the signer hashed, even
/// when multiple prefixes resolve to the same URI (Keycloak-style assertions
/// declare both `xmlns="…"` and `xmlns:saml="…"` to the same URI).
fn lookup_prefix_for_uri(
    uri: Option<&str>,
    ancestor_chain: &[&Element],
    element: &Element,
    is_attribute: bool,
    source_prefix: Option<&str>,
) -> Result<Option<String>, Error> {
    let Some(uri) = uri else {
        return Ok(None);
    };
    if uri == XML_NS {
        return Ok(Some("xml".to_owned()));
    }
    let in_scope = namespaces_in_scope(element, ancestor_chain);
    prefix_for_uri(&in_scope, Some(uri), is_attribute, source_prefix)
}

/// Like [`lookup_prefix_for_uri`] but takes a pre-built in-scope set.
///
/// Selection order:
/// 1. If `source_prefix = Some(p)` and an in-scope binding for prefix `p`
///    resolves to `uri`, return `Some(p)`. (For attributes, this requires
///    `p` to be non-empty — attributes never use the default namespace.)
/// 2. Otherwise walk inward-to-outward and return the first (most deeply
///    nested) binding whose URI matches.
fn prefix_for_uri(
    in_scope: &[(Option<String>, String)],
    uri: Option<&str>,
    is_attribute: bool,
    source_prefix: Option<&str>,
) -> Result<Option<String>, Error> {
    let Some(uri) = uri else {
        return Ok(None);
    };
    if uri == XML_NS {
        return Ok(Some("xml".to_owned()));
    }

    // Step 1: prefer the prefix the signer wrote, if it is in scope and bound
    // to this URI. `source_prefix = Some("")` would be nonsensical XML so we
    // treat the bare-empty-string case as "no hint" and fall through.
    // Unprefixed source names (element default-ns binding) correspond to
    // `source_prefix = None` on the parsed value, which we represent here as
    // the absence of the hint.
    if let Some(hint) = source_prefix
        && !hint.is_empty()
    {
        for (prefix, decl_uri) in in_scope.iter().rev() {
            if decl_uri == uri
                && let Some(p) = prefix.as_deref()
                && p == hint
            {
                return Ok(Some(hint.to_owned()));
            }
        }
        // Hint not in scope for this URI — fall through to general lookup.
    }

    // Step 1b: if the caller passed no source-prefix hint, that means the
    // source either wrote no prefix (default-ns binding) or this value was
    // produced programmatically. For elements, prefer the default-ns binding
    // when it matches. Attributes never use the default namespace.
    if source_prefix.is_none() && !is_attribute {
        for (prefix, decl_uri) in in_scope.iter().rev() {
            if decl_uri == uri && prefix.is_none() {
                return Ok(None);
            }
        }
    }

    // Step 2: walk inward-to-outward; later (more deeply nested) declarations
    // win. For attributes we must use a named prefix (default ns doesn't
    // apply).
    for (prefix, decl_uri) in in_scope.iter().rev() {
        if decl_uri == uri {
            if is_attribute && prefix.is_none() {
                continue;
            }
            return Ok(prefix.clone());
        }
    }
    Err(Error::XmlEmit(format!(
        "no namespace prefix in scope for URI {uri}"
    )))
}

/// Look up the URI bound to `prefix` (None for default) in an in-scope set.
fn lookup_in_scope<'a>(
    in_scope: &'a [(Option<String>, String)],
    prefix: Option<&str>,
) -> Option<&'a str> {
    for (decl_prefix, uri) in in_scope.iter().rev() {
        if decl_prefix.as_deref() == prefix {
            return Some(uri.as_str());
        }
    }
    None
}

/// Push `(prefix, uri)` into `out` only if no entry with the same `prefix` is
/// already present.
fn push_unique(out: &mut Vec<(Option<String>, String)>, prefix: Option<String>, uri: String) {
    if !out.iter().any(|(p, _)| *p == prefix) {
        out.push((prefix, uri));
    }
}

/// Push `prefix` into `out` (a list of optional prefixes) only if absent.
fn push_unique_opt(out: &mut Vec<Option<String>>, prefix: Option<String>) {
    if !out.contains(&prefix) {
        out.push(prefix);
    }
}

/// Insert-or-overwrite a prefix binding (last write wins).
fn merge_rendered(out: &mut Vec<(Option<String>, String)>, prefix: Option<String>, uri: String) {
    if let Some(slot) = out.iter_mut().find(|(p, _)| *p == prefix) {
        slot.1 = uri;
    } else {
        out.push((prefix, uri));
    }
}

// =============================================================================
// Sort keys
// =============================================================================

/// Sort key for namespace declarations: default ns (no prefix) sorts before
/// any named prefix; named prefixes sort lexicographically by prefix bytes.
fn ns_sort_key(decl: &(Option<String>, String)) -> (u8, &[u8]) {
    match &decl.0 {
        None => (0, &[][..]),
        Some(p) => (1, p.as_bytes()),
    }
}

/// Sort key for attributes: (namespace URI as bytes, local name as bytes).
/// Unqualified attributes use URI "" and therefore sort before any namespaced
/// attribute (per C14N §3.7 step 3).
fn attr_sort_key(qname: &QName) -> (&[u8], &[u8]) {
    (
        qname.namespace().map_or(&[][..], str::as_bytes),
        qname.local().as_bytes(),
    )
}

// =============================================================================
// Output writers
// =============================================================================

fn push_qname(out: &mut Vec<u8>, prefix: Option<&str>, local: &str) {
    if let Some(p) = prefix {
        out.extend_from_slice(p.as_bytes());
        out.push(b':');
    }
    out.extend_from_slice(local.as_bytes());
}

/// Element text-content character escaping per C14N §1.3.1.4:
/// `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `\r` → `&#xD;`.
fn push_text_escaped(out: &mut Vec<u8>, text: &str) {
    for byte in text.bytes() {
        match byte {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            b => out.push(b),
        }
    }
}

/// Attribute-value character escaping per C14N §1.3.1.4:
/// `&` → `&amp;`, `<` → `&lt;`, `"` → `&quot;`,
/// `\t` → `&#x9;`, `\n` → `&#xA;`, `\r` → `&#xD;`.
fn push_attr_value_escaped(out: &mut Vec<u8>, value: &str) {
    for byte in value.bytes() {
        match byte {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\t' => out.extend_from_slice(b"&#x9;"),
            b'\n' => out.extend_from_slice(b"&#xA;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            b => out.push(b),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse::Document;
    use proptest::prelude::*;

    /// Parse XML, locate the element with the given local name (no namespace
    /// filter), and canonicalize it. The ancestor chain is computed by walking
    /// the document tree.
    fn canon_named(xml: &str, local: &str, algorithm: C14nAlgorithm, prefixes: &[&str]) -> String {
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let (target, chain) = find_with_chain(&doc, local).expect("find target");
        let bytes = canonicalize(&doc, target, &chain, algorithm, prefixes).expect("c14n");
        String::from_utf8(bytes).expect("utf-8 output")
    }

    fn canon_root(xml: &str, algorithm: C14nAlgorithm, prefixes: &[&str]) -> String {
        let doc = Document::parse(xml.as_bytes()).expect("parse");
        let bytes = canonicalize(&doc, doc.root(), &[], algorithm, prefixes).expect("c14n");
        String::from_utf8(bytes).expect("utf-8 output")
    }

    /// Find the first element (in document order) with the given local name
    /// and return it along with its ancestor chain (root → … → parent).
    fn find_with_chain<'a>(
        doc: &'a Document,
        local: &str,
    ) -> Option<(&'a Element, Vec<&'a Element>)> {
        fn walk<'b>(
            element: &'b Element,
            local: &str,
            chain: &mut Vec<&'b Element>,
        ) -> Option<(&'b Element, Vec<&'b Element>)> {
            if element.qname().local() == local {
                return Some((element, chain.clone()));
            }
            for child in element.children() {
                if let Node::Element(child_elem) = child {
                    chain.push(element);
                    if let Some(hit) = walk(child_elem, local, chain) {
                        return Some(hit);
                    }
                    chain.pop();
                }
            }
            None
        }
        let mut chain: Vec<&Element> = Vec::new();
        walk(doc.root(), local, &mut chain)
    }

    // ---------- Example 1: attribute order + entity escape ------------------

    #[test]
    fn exclusive_example_1_entity_escape() {
        let input = r#"<doc><e attr="value with &amp; and &lt;"/></doc>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(
            got,
            r#"<doc><e attr="value with &amp; and &lt;"></e></doc>"#
        );
    }

    // ---------- Example 2: default namespace --------------------------------

    #[test]
    fn exclusive_example_2_default_namespace() {
        let input = r#"<doc xmlns="urn:foo"><a/></doc>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, r#"<doc xmlns="urn:foo"><a></a></doc>"#);
    }

    #[test]
    fn inclusive_example_2_default_namespace() {
        let input = r#"<doc xmlns="urn:foo"><a/></doc>"#;
        let got = canon_root(input, C14nAlgorithm::InclusiveCanonical, &[]);
        assert_eq!(got, r#"<doc xmlns="urn:foo"><a></a></doc>"#);
    }

    // ---------- Example 3: unused namespace declarations --------------------

    #[test]
    fn exclusive_example_3_drops_unused_namespaces() {
        // The apex (doc) doesn't use `unused`; Exclusive drops it.
        let input = r#"<doc xmlns:unused="urn:unused"><e/></doc>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, "<doc><e></e></doc>");
    }

    #[test]
    fn inclusive_example_3_keeps_unused_namespaces_on_apex() {
        let input = r#"<doc xmlns:unused="urn:unused"><e/></doc>"#;
        let got = canon_root(input, C14nAlgorithm::InclusiveCanonical, &[]);
        assert_eq!(got, r#"<doc xmlns:unused="urn:unused"><e></e></doc>"#);
    }

    // ---------- Example 4: PrefixList inheritance ---------------------------

    #[test]
    fn exclusive_example_4_prefix_list_forces_inclusion() {
        // Canonicalize <apex> (not the root). `p` is declared on <root> but
        // not visibly used by <apex>; the PrefixList forces it in. `q` is
        // declared on apex but not visibly utilized by apex or its subtree,
        // so Exclusive C14N still drops it per spec.
        let input = r#"<root xmlns:p="urn:p"><apex xmlns:q="urn:q"><leaf/></apex></root>"#;
        let got = canon_named(input, "apex", C14nAlgorithm::ExclusiveCanonical, &["p"]);
        assert_eq!(got, r#"<apex xmlns:p="urn:p"><leaf></leaf></apex>"#);
    }

    #[test]
    fn exclusive_example_4_without_prefix_list_drops_unused() {
        // Same input, no PrefixList: `p` is not visibly used by apex's
        // subtree, so it is omitted; `q` is declared on apex itself but is
        // also not visibly used by apex/leaf, so it too is omitted.
        let input = r#"<root xmlns:p="urn:p"><apex xmlns:q="urn:q"><leaf/></apex></root>"#;
        let got = canon_named(input, "apex", C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, r"<apex><leaf></leaf></apex>");
    }

    // ---------- Example 5: attribute sorting --------------------------------

    #[test]
    fn exclusive_example_5_attribute_sorting() {
        let input = r#"<e xmlns:b="urn:b" xmlns:a="urn:a" b:z="1" a:y="2" x="3" b:w="4"><c/></e>"#;
        // Namespace decls sorted by prefix: a, b. Attributes sorted:
        // unqualified (`x`) first, then namespaced sorted by URI then local:
        // urn:a → a:y; urn:b → b:w then b:z.
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(
            got,
            r#"<e xmlns:a="urn:a" xmlns:b="urn:b" x="3" a:y="2" b:w="4" b:z="1"><c></c></e>"#
        );
    }

    #[test]
    fn inclusive_example_5_attribute_sorting() {
        let input = r#"<e xmlns:b="urn:b" xmlns:a="urn:a" b:z="1" a:y="2" x="3" b:w="4"><c/></e>"#;
        let got = canon_root(input, C14nAlgorithm::InclusiveCanonical, &[]);
        assert_eq!(
            got,
            r#"<e xmlns:a="urn:a" xmlns:b="urn:b" x="3" a:y="2" b:w="4" b:z="1"><c></c></e>"#
        );
    }

    // ---------- Example 6: comments preserved vs dropped --------------------

    #[test]
    fn exclusive_example_6_drops_comments() {
        let input = r"<doc><!-- comment --><e/></doc>";
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, "<doc><e></e></doc>");
    }

    #[test]
    fn exclusive_with_comments_example_6_preserves_comments() {
        let input = r"<doc><!-- comment --><e/></doc>";
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonicalWithComments, &[]);
        assert_eq!(got, "<doc><!-- comment --><e></e></doc>");
    }

    #[test]
    fn inclusive_example_6_drops_comments() {
        let input = r"<doc><!-- comment --><e/></doc>";
        let got = canon_root(input, C14nAlgorithm::InclusiveCanonical, &[]);
        assert_eq!(got, "<doc><e></e></doc>");
    }

    #[test]
    fn inclusive_with_comments_example_6_preserves_comments() {
        let input = r"<doc><!-- comment --><e/></doc>";
        let got = canon_root(input, C14nAlgorithm::InclusiveCanonicalWithComments, &[]);
        assert_eq!(got, "<doc><!-- comment --><e></e></doc>");
    }

    // ---------- Example 7: text whitespace preservation ---------------------

    #[test]
    fn exclusive_example_7_preserves_text_whitespace() {
        let input = "<doc>  text  </doc>";
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, "<doc>  text  </doc>");
    }

    #[test]
    fn inclusive_example_7_preserves_text_whitespace() {
        let input = "<doc>  text  </doc>";
        let got = canon_root(input, C14nAlgorithm::InclusiveCanonical, &[]);
        assert_eq!(got, "<doc>  text  </doc>");
    }

    // ---------- Additional spec-conformance vectors -------------------------

    #[test]
    fn empty_element_serializes_with_open_and_close_tags() {
        // Both `<e/>` and `<e></e>` must canonicalize to `<e></e>`.
        let a = canon_root("<e/>", C14nAlgorithm::ExclusiveCanonical, &[]);
        let b = canon_root("<e></e>", C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(a, "<e></e>");
        assert_eq!(b, "<e></e>");
        assert_eq!(a, b);
    }

    #[test]
    fn text_content_escapes_per_spec() {
        // `&`, `<`, `>` and `\r` are the only chars escaped in text content.
        // Newlines and tabs are preserved verbatim.
        let input = "<doc>a&amp;b&lt;c&gt;d\te\nf</doc>";
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        // Re-parser turned the entities into literal chars; we re-escape `&<>`.
        assert_eq!(got, "<doc>a&amp;b&lt;c&gt;d\te\nf</doc>");
    }

    #[test]
    fn attribute_value_escapes_per_spec() {
        // Build via XML so the parser normalizes the value, then check the
        // canonical re-emit applies the §1.3.1.4 attribute escapes.
        // Source uses entity refs to embed a tab/newline/CR/quote in the
        // attribute, since literal CR would be normalized to LF on parse.
        let input = r#"<e a="&#9;&#10;&#13;&quot;&amp;&lt;"/>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, r#"<e a="&#x9;&#xA;&#xD;&quot;&amp;&lt;"></e>"#);
    }

    #[test]
    fn xml_prefix_attribute_is_preserved_but_never_re_declared() {
        // xml:lang is always in scope. Exclusive C14N never renders the
        // implicit `xmlns:xml` binding.
        let input = r#"<doc xml:lang="en"><e/></doc>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, r#"<doc xml:lang="en"><e></e></doc>"#);
    }

    #[test]
    fn xml_namespaced_attribute_sorts_by_uri() {
        // xml:id attribute sorts after unqualified ones, by namespace URI.
        let input = r#"<e a="1" xml:id="x" b="2"/>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        // Sort order: unqualified attributes first by local name (a, b), then
        // namespaced sorted by URI (the xml URI) + local name.
        assert_eq!(got, r#"<e a="1" b="2" xml:id="x"></e>"#);
    }

    #[test]
    fn descendant_namespace_decl_not_re_emitted_on_descendant() {
        // The `p` binding on the apex is rendered on the apex; the same
        // binding declared again on a descendant is not re-emitted.
        let input = r#"<r xmlns:p="urn:p"><p:c><p:d/></p:c></r>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, r#"<r><p:c xmlns:p="urn:p"><p:d></p:d></p:c></r>"#);
    }

    #[test]
    fn descendant_overriding_default_namespace_is_emitted() {
        // Apex declares xmlns="urn:a"; descendant <b> overrides with
        // xmlns="urn:b". Both default-ns declarations are visibly utilized
        // by their respective elements and must appear in canonical output.
        let input = r#"<a xmlns="urn:a"><b xmlns="urn:b"/></a>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, r#"<a xmlns="urn:a"><b xmlns="urn:b"></b></a>"#);
    }

    #[test]
    fn descendant_cancels_default_namespace_with_empty_xmlns() {
        // Apex has xmlns="urn:a"; descendant explicitly cancels it with
        // xmlns="" and is itself unprefixed. Exclusive C14N must emit
        // xmlns="" on the descendant to cancel the inherited default ns.
        let input = r#"<a xmlns="urn:a"><b xmlns=""/></a>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(got, r#"<a xmlns="urn:a"><b xmlns=""></b></a>"#);
    }

    #[test]
    fn inclusive_propagates_unused_ns_only_to_apex() {
        // <root> declares `unused`. Inclusive C14N of <apex> (a descendant)
        // surfaces the ancestor declaration on the apex even though apex
        // does not visibly use it. The descendant <leaf> does NOT re-emit it.
        let input = r#"<root xmlns:unused="urn:unused"><apex><leaf/></apex></root>"#;
        let got = canon_named(input, "apex", C14nAlgorithm::InclusiveCanonical, &[]);
        assert_eq!(
            got,
            r#"<apex xmlns:unused="urn:unused"><leaf></leaf></apex>"#
        );
    }

    // ---------- External known-answer vector -------------------------------

    #[test]
    fn merlin_exclusive_c14n_known_answers() {
        // Reduced from the Merlin Hughes Exclusive C14N interoperability
        // vector distributed by xmlsec. Unlike the synthetic examples above,
        // these expected byte streams come from an independent implementation
        // and match the four published digest values in exc-signature.xml.
        // Provenance and license live alongside the fixture files.
        let input = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/common/c14n_vectors/merlin-exclusive-subset.xml"
        ));
        fn expected(fixture: &str) -> &str {
            fixture.strip_suffix('\n').unwrap_or(fixture)
        }

        assert_eq!(
            canon_named(input, "Object", C14nAlgorithm::ExclusiveCanonical, &[]),
            expected(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/common/c14n_vectors/exclusive-without-comments.xml"
            )))
        );
        assert_eq!(
            canon_named(
                input,
                "Object",
                C14nAlgorithm::ExclusiveCanonical,
                &["bar", "#default"],
            ),
            expected(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/common/c14n_vectors/exclusive-inclusive-prefixes-without-comments.xml"
            )))
        );
        assert_eq!(
            canon_named(
                input,
                "Object",
                C14nAlgorithm::ExclusiveCanonicalWithComments,
                &[],
            ),
            expected(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/common/c14n_vectors/exclusive-with-comments.xml"
            )))
        );
        assert_eq!(
            canon_named(
                input,
                "Object",
                C14nAlgorithm::ExclusiveCanonicalWithComments,
                &["bar", "#default"],
            ),
            expected(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/common/c14n_vectors/exclusive-inclusive-prefixes-with-comments.xml"
            )))
        );
    }

    // ---------- PrefixList semantics ---------------------------------------

    #[test]
    fn exclusive_prefix_list_default_token_surfaces_default_ns() {
        // `#default` in PrefixList means "the default namespace". The ancestor
        // declares xmlns="urn:root"; canonicalizing <apex> with PrefixList
        // ["#default"] surfaces that default ns on apex even though apex
        // (unprefixed) would inherit it implicitly anyway. The key property
        // tested here is that we honor the `#default` token without panicking
        // and the binding ends up rendered on the apex.
        let input = r#"<root xmlns="urn:root"><apex><leaf/></apex></root>"#;
        let got = canon_named(
            input,
            "apex",
            C14nAlgorithm::ExclusiveCanonical,
            &["#default"],
        );
        // apex is unprefixed and the default-ns from root is in scope; whether
        // by visibly-utilized or by #default, it must be rendered on apex.
        assert_eq!(got, r#"<apex xmlns="urn:root"><leaf></leaf></apex>"#);
    }

    #[test]
    fn exclusive_prefix_list_unbound_prefix_silently_ignored() {
        // PrefixList contains "missing" which isn't in scope. Per spec, such
        // tokens are silently ignored.
        let input = r"<root><apex/></root>";
        let got = canon_named(
            input,
            "apex",
            C14nAlgorithm::ExclusiveCanonical,
            &["missing"],
        );
        assert_eq!(got, "<apex></apex>");
    }

    // ---------- SAML XSW-style fixture --------------------------------------

    #[test]
    fn saml_assertion_subtree_canonicalizes_deterministically() {
        // Synthetic SAML assertion: an element with an ID attribute, declared
        // namespaces, and namespaced child elements. The point is to confirm
        // that c14n is stable across structurally-equivalent inputs (different
        // attribute order in the source).
        let a = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="abc123" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>issuer.example.com</saml:Issuer></saml:Assertion>"#;
        let b = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="abc123" IssueInstant="2024-01-01T00:00:00Z" Version="2.0"><saml:Issuer>issuer.example.com</saml:Issuer></saml:Assertion>"#;
        let ca = canon_root(a, C14nAlgorithm::ExclusiveCanonical, &[]);
        let cb = canon_root(b, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(ca, cb);
        // Attributes must be sorted: ID, IssueInstant, Version (alphabetical
        // by local name, all unqualified).
        assert!(
            ca.starts_with(r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="abc123" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">"#),
            "got: {ca}"
        );
        // Child element retains its prefix.
        assert!(ca.contains("<saml:Issuer>issuer.example.com</saml:Issuer>"));
    }

    #[test]
    fn saml_response_attribute_sort_is_stable() {
        // <samlp:Response> typically has Destination, ID, IssueInstant,
        // InResponseTo, Version. Confirm canonical attribute order is by
        // local name (all unqualified). Source order is shuffled.
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="https://sp/acs" ID="resp-1" InResponseTo="req-1"><x/></samlp:Response>"#;
        let got = canon_root(xml, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert!(
            got.starts_with(r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp/acs" ID="resp-1" InResponseTo="req-1" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">"#),
            "got: {got}"
        );
    }

    #[test]
    fn nested_element_with_qualified_attribute_uses_correct_prefix() {
        // Element <ds:Reference> with ds:URI attribute. Canonical output
        // keeps the `ds:` prefix on both, and only renders the `ds`
        // declaration once on the outer apex.
        let input =
            r##"<ds:Signature xmlns:ds="urn:ds"><ds:Reference URI="#abc"/></ds:Signature>"##;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(
            got,
            r##"<ds:Signature xmlns:ds="urn:ds"><ds:Reference URI="#abc"></ds:Reference></ds:Signature>"##
        );
    }

    #[test]
    fn determinism_across_attribute_order_permutations() {
        // Same logical element, three different source orderings of equivalent
        // attributes — all must produce identical canonical output.
        let a = r#"<e b="2" a="1" c="3"/>"#;
        let b = r#"<e a="1" c="3" b="2"/>"#;
        let c = r#"<e c="3" b="2" a="1"/>"#;
        let ca = canon_root(a, C14nAlgorithm::ExclusiveCanonical, &[]);
        let cb = canon_root(b, C14nAlgorithm::ExclusiveCanonical, &[]);
        let cc = canon_root(c, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(ca, cb);
        assert_eq!(cb, cc);
        assert_eq!(ca, r#"<e a="1" b="2" c="3"></e>"#);
    }

    proptest! {
        #[test]
        fn canonicalization_is_idempotent_and_source_order_independent(
            attributes in proptest::collection::hash_map(
                "a[0-9]{1,3}",
                "[A-Za-z0-9 ]{0,20}",
                0..12,
            ),
            text in "[A-Za-z0-9 ]{0,40}",
        ) {
            fn source(attributes: &[(String, String)], text: &str) -> String {
                let mut xml = String::from("<e");
                for (name, value) in attributes {
                    xml.push(' ');
                    xml.push_str(name);
                    xml.push_str("=\"");
                    xml.push_str(value);
                    xml.push('"');
                }
                xml.push('>');
                xml.push_str(text);
                xml.push_str("</e>");
                xml
            }

            let forward = attributes.into_iter().collect::<Vec<_>>();
            let mut reversed = forward.clone();
            reversed.reverse();

            for algorithm in [
                C14nAlgorithm::ExclusiveCanonical,
                C14nAlgorithm::InclusiveCanonical,
            ] {
                let canonical = canon_root(&source(&forward, &text), algorithm, &[]);
                let reordered = canon_root(&source(&reversed, &text), algorithm, &[]);
                let canonical_again = canon_root(&canonical, algorithm, &[]);

                prop_assert_eq!(&canonical, &reordered);
                prop_assert_eq!(&canonical, &canonical_again);
            }
        }
    }

    // ---------- Keycloak-shape prefix-vs-default-ns regression --------------
    //
    // Real Keycloak SAMLResponses declare both the default xmlns and a
    // `xmlns:saml=` binding to the same URI on the same element, then write
    // the element name with the `saml:` prefix:
    //   <saml:Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
    //                   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    //                   ID="…" …>
    // Both prefixes resolve to the same URI, but the signer hashed the byte
    // sequence containing `saml:`. Exclusive XML-C14N requires the canonical
    // form to use the same prefix the signer used; otherwise the digest the
    // verifier computes will differ from the embedded `<ds:DigestValue>` and
    // signature verification fails with "digest mismatch". Before this fix,
    // `prefix_for_uri` walked the in-scope set in declaration order and
    // could pick the default (empty) prefix when it appeared later, dropping
    // the `saml:` prefix from canonical output. The fixed version honors the
    // source prefix recorded on `Element::source_prefix`.
    //
    // Cross-checked against lxml's c14n with `exclusive=True` (Python 3,
    // libxml2 2.x):
    //   <saml:Foo xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:Foo>
    //
    // We use a self-contained synthetic element here so the regression is
    // exercised in unit tests; the longer Keycloak SAMLResponse fixture lives
    // alongside the end-to-end integration tests.

    #[test]
    fn keycloak_shape_preserves_saml_prefix_default_xmlns_first() {
        // Source declares the default xmlns *first*, then the prefixed one.
        // Before the fix the c14n output rendered `xmlns="…"` and dropped the
        // `saml:` prefix on the element name.
        let input = r#"<saml:Foo xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        // lxml ground truth: only `xmlns:saml=` is rendered (the default
        // xmlns is not visibly utilized — the element uses the `saml:`
        // prefix), and the element name keeps the `saml:` prefix.
        assert_eq!(
            got,
            r#"<saml:Foo xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:Foo>"#
        );
    }

    #[test]
    fn keycloak_shape_preserves_saml_prefix_prefixed_xmlns_first() {
        // Same logical input, opposite declaration order in the source. The
        // canonical bytes must be identical to the case above — both forms
        // represent the same XML Infoset and must canonicalize the same way.
        let input = r#"<saml:Foo xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(
            got,
            r#"<saml:Foo xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:Foo>"#
        );
    }

    #[test]
    fn keycloak_shape_preserves_default_when_source_used_default() {
        // The mirror case: same dual declaration, but the element name has
        // *no* prefix in the source — the source bound it via the default
        // xmlns. The canonical form must preserve the default-ns binding,
        // not switch to `saml:`.
        let input = r#"<Foo xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        assert_eq!(
            got,
            r#"<Foo xmlns="urn:oasis:names:tc:SAML:2.0:assertion"></Foo>"#
        );
    }

    #[test]
    fn keycloak_shape_with_nested_assertion_subtree() {
        // The realistic case: a Keycloak-style `<saml:Assertion>` with the
        // ambiguous double declaration on the apex, a prefixed `<saml:Issuer>`
        // child, and an `ID` attribute. The canonical output must use
        // `saml:` consistently for both the element and the child element.
        let input = r#"<saml:Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="abc"><saml:Issuer>idp</saml:Issuer></saml:Assertion>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        // Exclusive C14N only renders visibly-utilized bindings on the apex:
        // `saml:` is utilized, the default xmlns is not — so it's dropped.
        // The `<saml:Issuer>` descendant inherits `saml:` from the apex and
        // does not re-render the binding.
        assert_eq!(
            got,
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="abc"><saml:Issuer>idp</saml:Issuer></saml:Assertion>"#
        );
    }

    #[test]
    fn keycloak_shape_attribute_with_dual_prefix_keeps_source_prefix() {
        // Attribute on a Keycloak-shape element: `saml:Foo` carries an
        // attribute `saml:Bar="…"`. The element declares two prefixes
        // resolving to the same URI; the attribute was written with `saml:`.
        // Canonical output must keep `saml:Bar`, not switch to a different
        // prefix bound to the same URI.
        let input = r#"<saml:Foo xmlns:other="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" saml:Bar="v"/>"#;
        let got = canon_root(input, C14nAlgorithm::ExclusiveCanonical, &[]);
        // Both `other:` and `saml:` are bound to the same URI in scope, but
        // only `saml:` is visibly utilized (by the element name and the
        // attribute). Canonical output keeps `saml:Bar` and renders only the
        // `xmlns:saml=` declaration.
        assert_eq!(
            got,
            r#"<saml:Foo xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" saml:Bar="v"></saml:Foo>"#
        );
    }
}
