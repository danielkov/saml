//! `<md:EntityDescriptor>` and `<md:EntitiesDescriptor>` parsing, plus the
//! atomic verify-then-parse helpers per RFC-006 §3 and §5.
//!
//! Shared low-level helpers (`parse_endpoint`, `parse_key_descriptors`,
//! `parse_optional_duration`, etc.) live here as `pub(crate)` items because
//! both `descriptor::idp` and `descriptor::sp` consume them. Centralizing the
//! XML walks means the `<md:KeyDescriptor>` cert-use partitioning rule
//! (RFC-006 §4) and the xs:duration grammar live in exactly one place.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::crypto::cert::X509Certificate;
use crate::descriptor::idp::IdpDescriptor;
use crate::descriptor::sp::SpDescriptor;
use crate::dsig::algorithms::SignatureAlgorithm;
use crate::dsig::verify::verify_signature;
use crate::error::Error;
use crate::nameid::NameIdFormat;
use crate::time::parse_xs_datetime;
use crate::xml::parse::{
    Document, Element, Node, TreeBuilder, XmlLimits, collect_namespace_decls, configure_reader,
    normalize_line_endings, raw_local_name, reject_doctype_or_pi,
};

// =============================================================================
// Namespace constants
// =============================================================================

pub(crate) const MD_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub(crate) const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

// =============================================================================
// Federation aggregate type
// =============================================================================

/// Parsed `<md:EntitiesDescriptor>` (or a single `<md:EntityDescriptor>`
/// promoted to an aggregate with one entry, for caller convenience).
pub struct EntitiesDescriptor {
    pub name: Option<String>,
    pub valid_until: Option<SystemTime>,
    pub entities: Vec<MetadataEntry>,
}

/// One entry in a federation aggregate.
pub enum MetadataEntry {
    Idp(IdpDescriptor),
    Sp(SpDescriptor),
    /// Some entities advertise both roles (Shibboleth proxies, for example).
    Dual(IdpDescriptor, SpDescriptor),
    /// AuthnAuthority, AttributeAuthority, PDP, etc. — out of scope for v0.1.
    Other,
}

impl MetadataEntry {
    /// The `entityID` this entry describes, or `None` for an [`Other`] entry
    /// (an `<md:EntityDescriptor>` carrying only role descriptors this crate
    /// does not model, whose `entityID` we never parsed).
    ///
    /// [`Other`]: MetadataEntry::Other
    pub fn entity_id(&self) -> Option<&str> {
        match self {
            // For a Dual entry both halves carry the same entityID by
            // construction (they are parsed from the same EntityDescriptor).
            MetadataEntry::Idp(idp) | MetadataEntry::Dual(idp, _) => Some(&idp.entity_id),
            MetadataEntry::Sp(sp) => Some(&sp.entity_id),
            MetadataEntry::Other => None,
        }
    }
}

impl EntitiesDescriptor {
    /// Parse a federation aggregate or a single-entity metadata document.
    ///
    /// Uses an aggregate-sized node ceiling ([`XmlLimits::aggregate`]) so real
    /// InCommon / eduGAIN aggregates — which exceed the default ~100k-node
    /// limit — parse successfully. To parse under tighter (or looser) limits,
    /// use [`from_metadata_xml_with_limits`](Self::from_metadata_xml_with_limits).
    pub fn from_metadata_xml(xml: &[u8]) -> Result<Self, Error> {
        Self::from_metadata_xml_with_limits(xml, XmlLimits::aggregate())
    }

    /// Parse a federation aggregate or single-entity metadata document under
    /// caller-supplied resource limits.
    ///
    /// [`from_metadata_xml`](Self::from_metadata_xml) calls this with
    /// [`XmlLimits::aggregate`]; pass a tighter [`XmlLimits`] when the input is
    /// known to be small and you want a smaller worst-case allocation bound.
    pub fn from_metadata_xml_with_limits(xml: &[u8], limits: XmlLimits) -> Result<Self, Error> {
        let doc = Document::parse_with_limits(xml, limits)?;
        Self::from_root_element(doc.root())
    }

    fn from_root_element(root: &Element) -> Result<Self, Error> {
        if !is_md_element(root, "EntitiesDescriptor") {
            // Promote a single EntityDescriptor into a one-entry aggregate.
            if is_md_element(root, "EntityDescriptor") {
                let entry = parse_entity_descriptor(root)?;
                return Ok(Self {
                    name: None,
                    valid_until: parse_optional_xs_datetime(root, "validUntil")?,
                    entities: vec![entry],
                });
            }
            return Err(Error::InvalidConfiguration {
                reason: "root is not <md:EntityDescriptor> or <md:EntitiesDescriptor>",
            });
        }

        let name = root.attribute(None, "Name").map(str::to_owned);
        let valid_until = parse_optional_xs_datetime(root, "validUntil")?;

        let mut entities = Vec::new();
        collect_entities(root, &mut entities)?;

        Ok(Self {
            name,
            valid_until,
            entities,
        })
    }

    /// Find an entry by its `entityID`, regardless of role. Returns the first
    /// match in document order.
    ///
    /// This is a linear scan over [`entities`](Self::entities). For repeated
    /// lookups against a large aggregate (InCommon publishes thousands of
    /// entities), build an index once with [`index_by_entity_id`] and query
    /// that instead.
    ///
    /// [`index_by_entity_id`]: Self::index_by_entity_id
    pub fn by_entity_id(&self, entity_id: &str) -> Option<&MetadataEntry> {
        self.entities
            .iter()
            .find(|entry| entry.entity_id() == Some(entity_id))
    }

    /// Build a `HashMap` from `entityID` to entry for O(1) repeated lookups.
    ///
    /// Federation aggregates with thousands of entities make the linear
    /// [`by_entity_id`] / [`find_idp`] / [`find_sp`] scans expensive when a
    /// caller resolves many entityIDs; constructing this index once amortizes
    /// the cost. [`Other`] entries (no `entityID`) are skipped. When a
    /// duplicate `entityID` appears the first entry in document order wins,
    /// matching the linear accessors.
    ///
    /// [`by_entity_id`]: Self::by_entity_id
    /// [`find_idp`]: Self::find_idp
    /// [`find_sp`]: Self::find_sp
    /// [`Other`]: MetadataEntry::Other
    pub fn index_by_entity_id(&self) -> HashMap<&str, &MetadataEntry> {
        let mut index = HashMap::with_capacity(self.entities.len());
        for entry in &self.entities {
            if let Some(id) = entry.entity_id() {
                index.entry(id).or_insert(entry);
            }
        }
        index
    }

    /// Find an IdP entity by entity ID.
    pub fn find_idp(&self, entity_id: &str) -> Option<&IdpDescriptor> {
        self.entities.iter().find_map(|entry| match entry {
            MetadataEntry::Idp(idp) | MetadataEntry::Dual(idp, _) if idp.entity_id == entity_id => {
                Some(idp)
            }
            _ => None,
        })
    }

    /// Find an SP entity by entity ID.
    pub fn find_sp(&self, entity_id: &str) -> Option<&SpDescriptor> {
        self.entities.iter().find_map(|entry| match entry {
            MetadataEntry::Sp(sp) | MetadataEntry::Dual(_, sp) if sp.entity_id == entity_id => {
                Some(sp)
            }
            _ => None,
        })
    }

    /// Iterate over all IdP descriptors (including the IdP half of Dual entries).
    pub fn iter_idps(&self) -> impl Iterator<Item = &IdpDescriptor> {
        self.entities.iter().filter_map(|e| match e {
            MetadataEntry::Idp(idp) | MetadataEntry::Dual(idp, _) => Some(idp),
            _ => None,
        })
    }

    /// Iterate over all SP descriptors (including the SP half of Dual entries).
    pub fn iter_sps(&self) -> impl Iterator<Item = &SpDescriptor> {
        self.entities.iter().filter_map(|e| match e {
            MetadataEntry::Sp(sp) | MetadataEntry::Dual(_, sp) => Some(sp),
            _ => None,
        })
    }
}

// =============================================================================
// Streaming / bounded parse
// =============================================================================

/// Control-flow signal returned by a [`stream_entities`] / [`stream_signed_entities`]
/// visitor: keep going or stop early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamControl {
    /// Continue to the next entity.
    Continue,
    /// Stop iterating; the stream parser returns `Ok(())` without visiting
    /// any further entities (useful for "find the one entityID I care about
    /// and bail" over a multi-megabyte aggregate).
    Stop,
}

/// Parse a federation aggregate one `<md:EntityDescriptor>` at a time,
/// invoking `visit` for each, **without** building the whole `Vec` of
/// entities or a single DOM over the entire file.
///
/// Memory characteristics: the parser scans the input with a streaming XML
/// reader and materializes a DOM for **one** `<md:EntityDescriptor>` subtree
/// at a time (built by a tree builder whose namespace scope is seeded with the
/// in-scope declarations of the ancestor `<md:EntitiesDescriptor>` wrappers, so
/// the lifted subtree's prefixes resolve), parses it into a [`MetadataEntry`],
/// hands it to the
/// visitor, and drops it before advancing. Peak additional memory is therefore
/// bounded by one normalized copy of the input (XML 1.0 §2.11 line-end
/// normalization, matching the eager path) plus the largest single entity
/// tree — never the full aggregate DOM. The input slice itself is still held by
/// the caller; this API does not stream off a socket.
///
/// Nested `<md:EntitiesDescriptor>` blocks are flattened, matching the
/// eager [`EntitiesDescriptor::from_metadata_xml`] path.
///
/// # Security
///
/// This is the **unverified** entry point — it parses attacker-influenced XML
/// directly. When the aggregate is signed and you are establishing trust off
/// that signature, use [`stream_signed_entities`], which verifies the
/// wrapping signature before any entity is yielded.
pub fn stream_entities<F>(metadata_xml: &[u8], visit: F) -> Result<(), Error>
where
    F: FnMut(MetadataEntry) -> StreamControl,
{
    stream_entities_inner(metadata_xml, visit)
}

/// Verify the aggregate's wrapping XML-DSig signature, then visit its entities
/// one at a time, stopping early when the visitor returns
/// [`StreamControl::Stop`].
///
/// Mirrors [`parse_signed_entities_descriptor`] for the visitor-driven path:
/// the signature over the `<md:EntitiesDescriptor>` root is checked **before**
/// any child entity is yielded, so a visitor never observes an entity from an
/// unverified aggregate.
///
/// # Trust model & memory
///
/// Verifying an enveloped signature over the aggregate root requires the whole
/// document as a unit (the signature covers the entire tree), so this path
/// parses the full DOM once — the same full-DOM cost the eager
/// [`parse_signed_entities_descriptor`] already pays. It then verifies the
/// wrapper signature on that parsed `Document` (including the XSW root-coverage
/// check in [`verify_metadata_signature`]) and walks the **already-parsed**
/// tree, handing each entity to the visitor. There is no second parser and no
/// raw-byte re-scan: re-streaming the bytes after a full parse would buy no
/// memory saving while forking a parallel parsing path. Peak memory is the
/// parsed aggregate DOM, which is unavoidable for signature verification.
///
/// When unverified, bounded-memory streaming is what you need (you are not
/// establishing trust off the wrapper signature), use [`stream_entities`].
pub fn stream_signed_entities<F>(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
    mut visit: F,
) -> Result<(), Error>
where
    F: FnMut(MetadataEntry) -> StreamControl,
{
    // Verification happens on the parsed DOM before any entity is yielded; the
    // walk below only ever sees a tree whose wrapper signature already checked
    // out, so the visitor cannot observe an entity from an unverified
    // aggregate.
    let doc = Document::parse_with_limits(metadata_xml, XmlLimits::aggregate())?;
    verify_metadata_signature_on_document(&doc, trusted_signing_cert)?;
    visit_entities(doc.root(), &mut visit).map(|_control| ())
}

/// Walk an already-parsed (and, on the signed path, already-verified) root,
/// flattening nested `<md:EntitiesDescriptor>` blocks and invoking `visit` for
/// each `<md:EntityDescriptor>`. Propagates [`StreamControl::Stop`] outward so
/// the caller halts the whole walk.
fn visit_entities<F>(root: &Element, visit: &mut F) -> Result<StreamControl, Error>
where
    F: FnMut(MetadataEntry) -> StreamControl,
{
    if is_md_element(root, "EntityDescriptor") {
        return Ok(visit(parse_entity_descriptor(root)?));
    }
    if is_md_element(root, "EntitiesDescriptor") {
        for child in root.children() {
            let Node::Element(elem) = child else { continue };
            let control = if is_md_element(elem, "EntityDescriptor") {
                visit(parse_entity_descriptor(elem)?)
            } else if is_md_element(elem, "EntitiesDescriptor") {
                visit_entities(elem, visit)?
            } else {
                StreamControl::Continue
            };
            if control == StreamControl::Stop {
                return Ok(StreamControl::Stop);
            }
        }
        return Ok(StreamControl::Continue);
    }
    Err(Error::InvalidConfiguration {
        reason: "root is not <md:EntityDescriptor> or <md:EntitiesDescriptor>",
    })
}

/// Upper bound on the number of nested `<md:EntitiesDescriptor>` /
/// `<md:EntityDescriptor>` levels the unverified streaming scan will descend,
/// and on the total entities it will visit. The eager DOM path is bounded by
/// [`XmlLimits`]; this streaming path builds no whole-document DOM, so it
/// carries its own explicit ceilings to keep an adversarial aggregate (deeply
/// nested wrappers, or an unbounded entity count) from exhausting the
/// namespace stack or running unboundedly. Both are generous relative to real
/// federation metadata (eduGAIN nests a handful of levels; InCommon publishes
/// tens of thousands of entities) yet finite.
const MAX_STREAM_DEPTH: usize = 100;
const MAX_STREAM_ENTITIES: usize = 10_000_000;

/// One frame of the unverified streaming reader's namespace stack: the
/// `(key, value)` `xmlns(:prefix)?` declarations literally written on an open
/// `<md:EntitiesDescriptor>` wrapper, plus the element depth at which that
/// wrapper sits (so the frame is popped exactly when the wrapper closes).
type NsFrame = (Vec<(Vec<u8>, Vec<u8>)>, usize);

fn stream_entities_inner<F>(metadata_xml: &[u8], mut visit: F) -> Result<(), Error>
where
    F: FnMut(MetadataEntry) -> StreamControl,
{
    stream_entity_elements(metadata_xml, |entity_root| {
        Ok(visit(parse_entity_descriptor(entity_root)?))
    })
}

/// Core of the unverified streaming scan: drive a streaming XML reader over the
/// (line-end-normalized) aggregate, build each `<md:EntityDescriptor>` subtree
/// into an [`Element`] one at a time via a seed-scoped [`TreeBuilder`], and hand
/// the finished entity tree to `visit` before dropping it.
///
/// [`stream_entities_inner`] layers entity parsing on top; tests use it directly
/// to inspect the lifted entity tree (e.g. to prove line-end normalization
/// matches the eager path).
fn stream_entity_elements<F>(metadata_xml: &[u8], mut visit: F) -> Result<(), Error>
where
    F: FnMut(&Element) -> Result<StreamControl, Error>,
{
    use quick_xml::Reader;
    use quick_xml::events::Event;

    // XML 1.0 §2.11 end-of-line normalization, applied to the whole input up
    // front exactly as the eager DOM path does in `parse_inner`. Without it a
    // streamed entity carrying `\r`/`\r\n` in a text node or attribute value
    // would build a tree that differs from the eager one — this crate's c14n
    // escapes a literal `\r` as `&#xD;`, so the divergence is signature-relevant.
    // `normalize_line_endings` stays zero-copy on the common LF-only input.
    let normalized = normalize_line_endings(metadata_xml);
    let mut reader = Reader::from_reader(normalized.as_ref());
    configure_reader(&mut reader);

    // In-scope namespace declarations, one frame per open
    // `<md:EntitiesDescriptor>` wrapper (plus the root). When an entity subtree
    // is lifted out for isolated parsing it must see every prefix the original
    // document had in scope at that point — not just the outermost root's — so a
    // nested wrapper that introduces a prefix a child relies on still resolves
    // (RFC-006 §3 nested aggregates). Each frame holds the `(key, value)`
    // namespace declarations on that wrapper plus the element depth at which it
    // opened, so it is popped exactly when that wrapper closes.
    let mut ns_stack: Vec<NsFrame> = Vec::new();
    let mut root_seen = false;
    let mut root_is_aggregate = false;

    // Element depth at which the entity currently being captured started, and
    // the in-progress [`TreeBuilder`] accumulating that entity's subtree. Both
    // are `None`/empty when not inside an entity. The builder is seeded with the
    // ancestor wrappers' in-scope declarations and fed the entity's own events
    // (`Start` .. matching `End`) so prefixes resolve through the crate's single
    // namespace implementation — no byte-span capture or synthetic re-wrap.
    let mut capture_start: Option<usize> = None;
    let mut builder: Option<TreeBuilder> = None;
    let mut element_depth: usize = 0;
    let mut entities_visited: usize = 0;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| Error::XmlParse(format!("quick-xml: {e}")))?;
        if matches!(event, Event::Eof) {
            break;
        }

        // While inside an entity, every event is fed to the builder verbatim so
        // the lifted subtree is constructed identically to the eager DOM path.
        if let Some(b) = builder.as_mut() {
            b.feed(&event)?;
        }

        match &event {
            Event::DocType(_) | Event::PI(_) => {
                // The builder (when active) already rejected these; reject on
                // the bare-aggregate path too.
                return Err(reject_doctype_or_pi(&event)
                    .unwrap_or_else(|| Error::XmlParse("unexpected event".to_string())));
            }
            Event::Start(start) => {
                let local = raw_local_name(start.name().into_inner());
                if !root_seen {
                    root_seen = true;
                    root_is_aggregate = local == b"EntitiesDescriptor";
                    if !root_is_aggregate && local != b"EntityDescriptor" {
                        return Err(Error::InvalidConfiguration {
                            reason: "root is not <md:EntityDescriptor> or <md:EntitiesDescriptor>",
                        });
                    }
                    if root_is_aggregate {
                        ns_stack.push((collect_namespace_decls(start), element_depth));
                    } else {
                        // A single EntityDescriptor root is itself the one
                        // entry; begin capturing from this opening tag.
                        capture_start = Some(0);
                        builder = Some(new_entity_builder(&ns_stack)?);
                        feed_open(&mut builder, &event)?;
                    }
                    element_depth = element_depth.checked_add(1).ok_or_else(depth_overflow)?;
                    continue;
                }
                if capture_start.is_none() {
                    if local == b"EntityDescriptor" {
                        capture_start = Some(element_depth);
                        builder = Some(new_entity_builder(&ns_stack)?);
                        feed_open(&mut builder, &event)?;
                    } else if local == b"EntitiesDescriptor" {
                        // Descended into a nested wrapper: push its declarations
                        // (tagged with this element's sit-depth) so children
                        // inherit the full in-scope prefix set.
                        if ns_stack.len() >= MAX_STREAM_DEPTH {
                            return Err(Error::XmlParse(
                                "nested EntitiesDescriptor depth limit exceeded".to_string(),
                            ));
                        }
                        ns_stack.push((collect_namespace_decls(start), element_depth));
                    }
                }
                element_depth = element_depth.checked_add(1).ok_or_else(depth_overflow)?;
            }
            Event::Empty(empty) => {
                let local = raw_local_name(empty.name().into_inner());
                if !root_seen {
                    // An empty-element root carries no entities; nothing to do.
                    if local != b"EntitiesDescriptor" && local != b"EntityDescriptor" {
                        return Err(Error::InvalidConfiguration {
                            reason: "root is not <md:EntityDescriptor> or <md:EntitiesDescriptor>",
                        });
                    }
                    break;
                }
            }
            Event::End(_) => {
                element_depth = element_depth
                    .checked_sub(1)
                    .ok_or_else(|| Error::XmlParse("unmatched end tag".to_string()))?;
                if Some(element_depth) == capture_start {
                    // The entity's closing tag was just fed to the builder
                    // above; finalize its tree, hand it to the visitor, and drop
                    // it before advancing — only one entity is ever materialized
                    // at once.
                    let entity_root = builder
                        .take()
                        .ok_or_else(|| Error::XmlParse("entity builder missing".to_string()))?
                        .finish_root()?;
                    capture_start = None;
                    entities_visited = entities_visited
                        .checked_add(1)
                        .ok_or_else(|| Error::XmlParse("entity count overflow".to_string()))?;
                    if entities_visited > MAX_STREAM_ENTITIES {
                        return Err(Error::XmlParse(
                            "aggregate entity count limit exceeded".to_string(),
                        ));
                    }
                    if visit(&entity_root)? == StreamControl::Stop {
                        return Ok(());
                    }
                    if !root_is_aggregate {
                        // Single-entity root: only ever one entry.
                        break;
                    }
                } else if capture_start.is_none()
                    && ns_stack.len() > 1
                    && ns_stack
                        .last()
                        .is_some_and(|(_, depth)| *depth == element_depth)
                {
                    // Ascended out of a nested wrapper sitting at this depth;
                    // its declarations leave scope. The root frame (index 0)
                    // always stays in scope until EOF.
                    ns_stack.pop();
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn depth_overflow() -> Error {
    Error::XmlParse("depth overflow".to_string())
}

/// Build a fresh [`TreeBuilder`] for one captured entity, seeded with the
/// in-scope namespace declarations of every open ancestor `<md:EntitiesDescriptor>`
/// wrapper. The declarations are collapsed innermost-wins (a nested wrapper that
/// redeclares a prefix shadows the outer binding, exactly as in the source
/// document) and deduped by key while preserving outermost-first order.
fn new_entity_builder(ns_stack: &[NsFrame]) -> Result<TreeBuilder, Error> {
    let mut seed: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (frame, _depth) in ns_stack {
        for (key, value) in frame {
            if let Some(slot) = seed.iter_mut().find(|(k, _)| k == key) {
                slot.1.clone_from(value);
            } else {
                seed.push((key.clone(), value.clone()));
            }
        }
    }
    TreeBuilder::with_seed_scope(XmlLimits::aggregate(), &seed)
}

/// Feed the opening `Start` event of a just-detected entity into the freshly
/// created builder. Factored out so the root and nested-child capture sites
/// share one place that asserts the builder is present.
fn feed_open(
    builder: &mut Option<TreeBuilder>,
    event: &quick_xml::events::Event<'_>,
) -> Result<(), Error> {
    builder
        .as_mut()
        .ok_or_else(|| Error::XmlParse("entity builder missing".to_string()))?
        .feed(event)
}

/// Recursively flatten nested `<md:EntitiesDescriptor>` blocks (RFC-006 §3).
fn collect_entities(
    entities_descriptor: &Element,
    out: &mut Vec<MetadataEntry>,
) -> Result<(), Error> {
    for child in entities_descriptor.children() {
        let Node::Element(elem) = child else { continue };
        if is_md_element(elem, "EntityDescriptor") {
            out.push(parse_entity_descriptor(elem)?);
        } else if is_md_element(elem, "EntitiesDescriptor") {
            collect_entities(elem, out)?;
        }
        // Other md:* extensions (RoleDescriptor, etc.) are ignored.
    }
    Ok(())
}

fn parse_entity_descriptor(entity: &Element) -> Result<MetadataEntry, Error> {
    let has_idp = entity
        .child_element(Some(MD_NS), "IDPSSODescriptor")
        .is_some();
    let has_sp = entity
        .child_element(Some(MD_NS), "SPSSODescriptor")
        .is_some();

    match (has_idp, has_sp) {
        (true, true) => {
            let idp = IdpDescriptor::from_entity_descriptor_element(entity)?;
            let sp = SpDescriptor::from_entity_descriptor_element(entity)?;
            Ok(MetadataEntry::Dual(idp, sp))
        }
        (true, false) => Ok(MetadataEntry::Idp(
            IdpDescriptor::from_entity_descriptor_element(entity)?,
        )),
        (false, true) => Ok(MetadataEntry::Sp(
            SpDescriptor::from_entity_descriptor_element(entity)?,
        )),
        (false, false) => Ok(MetadataEntry::Other),
    }
}

// =============================================================================
// Metadata signature verification & verify-then-parse helpers
// =============================================================================

/// Inputs for `verify_metadata_signature`. Bundled into a struct so callers
/// don't accidentally swap the cert / XML arguments.
pub struct VerifyMetadata<'a> {
    pub metadata_xml: &'a [u8],
    pub trusted_signing_cert: &'a X509Certificate,
}

/// Verify the enveloped XML-DSig on a metadata document.
///
/// The signed element MUST be the document root (the top-level
/// `<md:EntityDescriptor>` or `<md:EntitiesDescriptor>`). Any other arrangement
/// — for example, a signature whose `Reference URI` points at a descendant
/// while the attacker wraps the document in an outer envelope — is rejected
/// here. This is the structural XSW defense documented in RFC-002 §3.2 applied
/// at the metadata layer.
pub fn verify_metadata_signature(input: VerifyMetadata<'_>) -> Result<(), Error> {
    let doc = Document::parse(input.metadata_xml)?;
    verify_metadata_signature_on_document(&doc, input.trusted_signing_cert)
}

fn verify_metadata_signature_on_document(
    doc: &Document,
    trusted_signing_cert: &X509Certificate,
) -> Result<(), Error> {
    let signature_elem = doc
        .root()
        .child_element(Some(DS_NS), "Signature")
        .ok_or(Error::SignatureMissing)?;
    let verified = verify_signature(
        doc,
        signature_elem,
        std::slice::from_ref(trusted_signing_cert),
        SignatureAlgorithm::DEFAULTS,
    )?;
    if verified.signed_element != doc.root().id() {
        return Err(Error::SignatureVerification {
            reason: "metadata signature does not cover the document root",
        });
    }
    Ok(())
}

/// Verify the XML-DSig signature on a federation metadata document, then parse
/// it. Per RFC-006 §5, the verify-then-parse ordering is enforced atomically
/// here so attacker-supplied XML is never parsed into a usable descriptor
/// before the signature check runs.
pub fn parse_signed_entities_descriptor(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
) -> Result<EntitiesDescriptor, Error> {
    // Aggregate-sized node ceiling: a signed InCommon / eduGAIN aggregate
    // exceeds the default ~100k-node limit, and the signature covers the whole
    // wrapper so the document must be parsed as a unit before verification.
    let doc = Document::parse_with_limits(metadata_xml, XmlLimits::aggregate())?;
    verify_metadata_signature_on_document(&doc, trusted_signing_cert)?;
    EntitiesDescriptor::from_root_element(doc.root())
}

/// Verify-then-parse helper for a single-entity IdP metadata document.
pub fn parse_signed_idp_descriptor(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
) -> Result<IdpDescriptor, Error> {
    let doc = Document::parse(metadata_xml)?;
    verify_metadata_signature_on_document(&doc, trusted_signing_cert)?;
    let entity = find_entity_descriptor(doc.root(), |e| {
        e.child_element(Some(MD_NS), "IDPSSODescriptor").is_some()
    })
    .ok_or(Error::InvalidConfiguration {
        reason: "metadata does not contain an IdP entity",
    })?;
    IdpDescriptor::from_entity_descriptor_element(entity)
}

/// Verify-then-parse helper for a single-entity SP metadata document.
pub fn parse_signed_sp_descriptor(
    metadata_xml: &[u8],
    trusted_signing_cert: &X509Certificate,
) -> Result<SpDescriptor, Error> {
    let doc = Document::parse(metadata_xml)?;
    verify_metadata_signature_on_document(&doc, trusted_signing_cert)?;
    let entity = find_entity_descriptor(doc.root(), |e| {
        e.child_element(Some(MD_NS), "SPSSODescriptor").is_some()
    })
    .ok_or(Error::InvalidConfiguration {
        reason: "metadata does not contain an SP entity",
    })?;
    SpDescriptor::from_entity_descriptor_element(entity)
}

// =============================================================================
// Shared parsing helpers (consumed by descriptor::idp and descriptor::sp)
// =============================================================================

pub(crate) fn is_md_element(element: &Element, local: &str) -> bool {
    element.qname().local() == local && element.qname().namespace() == Some(MD_NS)
}

/// Locate an `<md:EntityDescriptor>` in `root` (which may itself be one or be
/// an `<md:EntitiesDescriptor>` aggregate) that satisfies `pred`.
///
/// For aggregates the search is in document order, flattening any nested
/// `<md:EntitiesDescriptor>` blocks (RFC-006 §3).
pub(crate) fn find_entity_descriptor<F>(root: &Element, pred: F) -> Option<&Element>
where
    F: Fn(&Element) -> bool + Copy,
{
    if is_md_element(root, "EntityDescriptor") {
        if pred(root) {
            return Some(root);
        }
        return None;
    }
    if is_md_element(root, "EntitiesDescriptor") {
        for child in root.children() {
            let Node::Element(elem) = child else { continue };
            if is_md_element(elem, "EntityDescriptor") {
                if pred(elem) {
                    return Some(elem);
                }
            } else if is_md_element(elem, "EntitiesDescriptor")
                && let Some(found) = find_entity_descriptor(elem, pred)
            {
                return Some(found);
            }
        }
    }
    None
}

/// Parse a `Binding=` / `Location=` / `index=` / `isDefault=` SAML endpoint.
pub(crate) fn parse_endpoint(element: &Element) -> Result<crate::binding::Endpoint, Error> {
    let binding_uri = element
        .attribute(None, "Binding")
        .ok_or(Error::InvalidConfiguration {
            reason: "endpoint missing Binding",
        })?;
    let binding = crate::binding::Binding::from_uri(binding_uri)?;
    let location = element
        .attribute(None, "Location")
        .ok_or(Error::InvalidConfiguration {
            reason: "endpoint missing Location",
        })?
        .to_owned();
    let index = match element.attribute(None, "index") {
        Some(s) => Some(
            s.parse::<u16>()
                .map_err(|_parse_err| Error::InvalidConfiguration {
                    reason: "endpoint index is not a u16",
                })?,
        ),
        None => None,
    };
    let is_default =
        parse_optional_bool_value(element.attribute(None, "isDefault"))?.unwrap_or(false);
    Ok(crate::binding::Endpoint {
        url: location,
        binding,
        index,
        is_default,
    })
}

/// Partition `<md:KeyDescriptor>` children into `(signing_certs,
/// encryption_certs)` per RFC-006 §4. A `KeyDescriptor` with no `use`
/// attribute lands in *both* lists.
pub(crate) fn parse_key_descriptors(
    role_descriptor: &Element,
) -> Result<(Vec<X509Certificate>, Vec<X509Certificate>), Error> {
    let mut signing = Vec::new();
    let mut encryption = Vec::new();

    for kd in role_descriptor.all_child_elements(Some(MD_NS), "KeyDescriptor") {
        let use_attr = kd.attribute(None, "use");
        let goes_to_signing = use_attr == Some("signing") || use_attr.is_none();
        let goes_to_encryption = use_attr == Some("encryption") || use_attr.is_none();

        // Reject explicit but unrecognized `use` values to surface metadata
        // typos rather than silently dropping the cert from both lists.
        if let Some(value) = use_attr
            && value != "signing"
            && value != "encryption"
        {
            return Err(Error::InvalidConfiguration {
                reason: "KeyDescriptor use attribute must be signing or encryption",
            });
        }

        let key_info =
            kd.child_element(Some(DS_NS), "KeyInfo")
                .ok_or(Error::InvalidConfiguration {
                    reason: "KeyDescriptor missing KeyInfo",
                })?;

        for x509_data in key_info.all_child_elements(Some(DS_NS), "X509Data") {
            for cert_elem in x509_data.all_child_elements(Some(DS_NS), "X509Certificate") {
                let b64 = cert_elem.text_content();
                let cert = X509Certificate::from_base64_x509(&b64)?;
                if goes_to_signing {
                    signing.push(cert.clone());
                }
                if goes_to_encryption {
                    encryption.push(cert);
                }
            }
        }
    }

    Ok((signing, encryption))
}

/// Collect every `<md:NameIDFormat>` child of a role descriptor and map each
/// to a [`NameIdFormat`]. Whitespace-only entries are dropped silently — the
/// SAML schema permits them but they carry no information.
pub(crate) fn parse_name_id_formats(role_descriptor: &Element) -> Vec<NameIdFormat> {
    let mut out = Vec::new();
    for child in role_descriptor.all_child_elements(Some(MD_NS), "NameIDFormat") {
        let uri = child.text_content();
        let trimmed = uri.trim();
        if !trimmed.is_empty() {
            out.push(NameIdFormat::from_uri(trimmed));
        }
    }
    out
}

/// Parse a `validUntil` (xs:dateTime) attribute on `element` if present.
pub(crate) fn parse_optional_xs_datetime(
    element: &Element,
    attr: &str,
) -> Result<Option<SystemTime>, Error> {
    match element.attribute(None, attr) {
        Some(s) => Ok(Some(parse_xs_datetime(s)?)),
        None => Ok(None),
    }
}

/// Parse a `cacheDuration` (xs:duration) attribute on `element` if present.
pub(crate) fn parse_optional_duration(
    element: &Element,
    attr: &str,
) -> Result<Option<Duration>, Error> {
    match element.attribute(None, attr) {
        Some(s) => Ok(Some(parse_xs_duration(s)?)),
        None => Ok(None),
    }
}

/// Parse a `WantAuthnRequestsSigned` / `AuthnRequestsSigned` /
/// `WantAssertionsSigned` style boolean attribute on `element`.
pub(crate) fn parse_optional_bool(element: &Element, attr: &str) -> Result<Option<bool>, Error> {
    parse_optional_bool_value(element.attribute(None, attr))
}

fn parse_optional_bool_value(value: Option<&str>) -> Result<Option<bool>, Error> {
    match value {
        None => Ok(None),
        // xs:boolean lexical space.
        Some("true" | "1") => Ok(Some(true)),
        Some("false" | "0") => Ok(Some(false)),
        Some(_) => Err(Error::InvalidConfiguration {
            reason: "invalid xs:boolean attribute",
        }),
    }
}

/// Parse an xs:duration of the common subset supported by this crate.
///
/// Accepted grammar (state-machine; no regex dependency):
///
/// ```text
/// P [ <digits> D ] [ T [ <digits> H ] [ <digits> M ] [ <digits> S ] ]
/// ```
///
/// Anything else (`Y` / `M` for years/months, negative durations, fractional
/// digits, or whitespace) is rejected with
/// `Error::InvalidConfiguration { reason: "unsupported xs:duration" }`.
pub(crate) fn parse_xs_duration(s: &str) -> Result<Duration, Error> {
    let unsupported = || Error::InvalidConfiguration {
        reason: "unsupported xs:duration",
    };

    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'P') {
        return Err(unsupported());
    }
    // We require at least one component (P alone, PT alone are invalid).
    if bytes.len() < 3 {
        return Err(unsupported());
    }

    // Phase tracking: 0 = before T (D allowed), 1 = after T (H, M, S allowed).
    // Within each phase we require designators in canonical order: D, then T,
    // then H, M, S. A repeated or out-of-order designator is an error.
    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    enum Slot {
        Days,
        Hours,
        Minutes,
        Seconds,
    }

    let mut i = 1usize;
    let mut after_t = false;
    let mut last_slot: Option<Slot> = None;
    let mut days: u64 = 0;
    let mut hours: u64 = 0;
    let mut minutes: u64 = 0;
    let mut seconds: u64 = 0;
    let mut saw_any = false;

    while let Some(&b) = bytes.get(i) {
        if b == b'T' {
            if after_t {
                return Err(unsupported());
            }
            after_t = true;
            i = i.checked_add(1).ok_or_else(unsupported)?;
            // After T we require at least one designator.
            if i >= bytes.len() {
                return Err(unsupported());
            }
            continue;
        }
        if !b.is_ascii_digit() {
            return Err(unsupported());
        }
        let start = i;
        while let Some(byte) = bytes.get(i)
            && byte.is_ascii_digit()
        {
            i = i.checked_add(1).ok_or_else(unsupported)?;
        }
        let designator = *bytes.get(i).ok_or_else(unsupported)?;
        let digit_slice = bytes.get(start..i).ok_or_else(unsupported)?;
        let value: u64 = std::str::from_utf8(digit_slice)
            .map_err(|_utf8_err| unsupported())?
            .parse::<u64>()
            .map_err(|_parse_err| unsupported())?;

        let (slot, target) = match (after_t, designator) {
            (false, b'D') => (Slot::Days, &mut days),
            (true, b'H') => (Slot::Hours, &mut hours),
            (true, b'M') => (Slot::Minutes, &mut minutes),
            (true, b'S') => (Slot::Seconds, &mut seconds),
            // Years / months (before T) and anything else are rejected.
            _ => return Err(unsupported()),
        };

        // Designators must appear at most once, and in canonical order.
        if let Some(prev) = last_slot
            && slot <= prev
        {
            return Err(unsupported());
        }
        last_slot = Some(slot);
        *target = value;
        saw_any = true;
        i = i.checked_add(1).ok_or_else(unsupported)?;
    }

    if !saw_any {
        return Err(unsupported());
    }

    // Compose into total seconds. None of the supported components can
    // realistically overflow u64 seconds for sane SAML metadata.
    let total_secs = days
        .checked_mul(86_400)
        .and_then(|d| d.checked_add(hours.checked_mul(3600)?))
        .and_then(|d| d.checked_add(minutes.checked_mul(60)?))
        .and_then(|d| d.checked_add(seconds))
        .ok_or_else(unsupported)?;

    Ok(Duration::from_secs(total_secs))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{Binding, SsoResponseBinding};
    use crate::crypto::cert::X509Certificate;
    use crate::crypto::cert::test_vectors::{RSA_CERT_PEM, RSA_KEY_PKCS8_PEM};
    use crate::crypto::keypair::KeyPair;
    use crate::dsig::algorithms::{C14nAlgorithm, DigestAlgorithm, SignatureAlgorithm};
    use crate::dsig::c14n::canonicalize;
    use crate::dsig::reference::ancestor_chain;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    fn rsa_cert_b64() -> String {
        X509Certificate::from_pem(RSA_CERT_PEM)
            .unwrap()
            .to_base64_x509()
    }

    fn rsa_cert() -> X509Certificate {
        X509Certificate::from_pem(RSA_CERT_PEM).unwrap()
    }

    // ---- xs:duration ----

    #[test]
    fn duration_pt1h() {
        assert_eq!(parse_xs_duration("PT1H").unwrap(), Duration::from_hours(1));
    }

    #[test]
    fn duration_pt15m() {
        assert_eq!(parse_xs_duration("PT15M").unwrap(), Duration::from_mins(15));
    }

    #[test]
    fn duration_p1d() {
        assert_eq!(parse_xs_duration("P1D").unwrap(), Duration::from_hours(24));
    }

    #[test]
    fn duration_pt3600s() {
        assert_eq!(
            parse_xs_duration("PT3600S").unwrap(),
            Duration::from_hours(1)
        );
    }

    #[test]
    fn duration_compound_hms() {
        assert_eq!(
            parse_xs_duration("PT1H30M15S").unwrap(),
            Duration::from_secs(3600 + 30 * 60 + 15)
        );
    }

    #[test]
    fn duration_p1d_pt1h() {
        assert_eq!(
            parse_xs_duration("P1DT1H").unwrap(),
            Duration::from_hours(25)
        );
    }

    #[test]
    fn duration_rejects_years() {
        assert!(matches!(
            parse_xs_duration("P1Y"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn duration_rejects_months() {
        assert!(matches!(
            parse_xs_duration("P1M"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn duration_rejects_negative() {
        assert!(matches!(
            parse_xs_duration("-PT1H"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn duration_rejects_empty_payload() {
        assert!(matches!(
            parse_xs_duration("P"),
            Err(Error::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            parse_xs_duration("PT"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn duration_rejects_repeated_designator() {
        assert!(matches!(
            parse_xs_duration("PT1H1H"),
            Err(Error::InvalidConfiguration { .. })
        ));
    }

    // ---- EntitiesDescriptor ----

    fn idp_entity_xml(entity_id: &str) -> String {
        format!(
            r#"<md:EntityDescriptor entityID="{eid}">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="https://idp.example.com/sso"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#,
            eid = entity_id,
            cert = rsa_cert_b64()
        )
    }

    fn sp_entity_xml(entity_id: &str) -> String {
        format!(
            r#"<md:EntityDescriptor entityID="{entity_id}">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                                  AuthnRequestsSigned="true"
                                  WantAssertionsSigned="true">
                <md:AssertionConsumerService index="0" isDefault="true"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://sp.example.com/acs"/>
                <md:SingleLogoutService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    Location="https://sp.example.com/slo"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#
        )
    }

    fn dual_entity_xml(entity_id: &str) -> String {
        format!(
            r#"<md:EntityDescriptor entityID="{eid}">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="https://entity.example.com/sso"/>
              </md:IDPSSODescriptor>
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService index="0" isDefault="true"
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="https://entity.example.com/acs"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>"#,
            eid = entity_id,
            cert = rsa_cert_b64()
        )
    }

    #[test]
    fn aggregate_with_mixed_children() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                       Name="urn:example:federation">
                {idp}
                {sp}
              </md:EntitiesDescriptor>"#,
            idp = idp_entity_xml("https://idp.example.com/saml"),
            sp = sp_entity_xml("https://sp.example.com/saml")
        );
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).expect("parse ok");
        assert_eq!(fed.name.as_deref(), Some("urn:example:federation"));
        assert_eq!(fed.entities.len(), 2);
        assert!(matches!(fed.entities[0], MetadataEntry::Idp(_)));
        assert!(matches!(fed.entities[1], MetadataEntry::Sp(_)));

        assert!(fed.find_idp("https://idp.example.com/saml").is_some());
        assert!(fed.find_sp("https://sp.example.com/saml").is_some());
        assert!(fed.find_idp("does-not-exist").is_none());
        assert_eq!(fed.iter_idps().count(), 1);
        assert_eq!(fed.iter_sps().count(), 1);
    }

    #[test]
    fn aggregate_flattens_nested_entities_descriptor() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {idp_outer}
                <md:EntitiesDescriptor>
                  {idp_inner}
                </md:EntitiesDescriptor>
              </md:EntitiesDescriptor>"#,
            idp_outer = idp_entity_xml("https://idp.outer.example.com/saml"),
            idp_inner = idp_entity_xml("https://idp.inner.example.com/saml")
        );
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities.len(), 2);
        assert!(fed.find_idp("https://idp.outer.example.com/saml").is_some());
        assert!(fed.find_idp("https://idp.inner.example.com/saml").is_some());
    }

    #[test]
    fn dual_role_entity_classified_as_dual() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {dual}
              </md:EntitiesDescriptor>"#,
            dual = dual_entity_xml("https://shib.example.com/saml")
        );
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities.len(), 1);
        assert!(matches!(fed.entities[0], MetadataEntry::Dual(_, _)));
        let idp = fed.find_idp("https://shib.example.com/saml").unwrap();
        let sp = fed.find_sp("https://shib.example.com/saml").unwrap();
        assert_eq!(idp.entity_id, sp.entity_id);
        assert_eq!(idp.sso_endpoints.len(), 1);
        assert_eq!(sp.assertion_consumer_services.len(), 1);
    }

    #[test]
    fn unknown_role_descriptor_becomes_other_variant() {
        let xml = r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
                <md:EntityDescriptor entityID="https://aa.example.com/saml">
                  <!-- An entity without IDP/SP role descriptors, e.g. an AttributeAuthority. -->
                  <md:AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
                </md:EntityDescriptor>
              </md:EntitiesDescriptor>"#;
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities.len(), 1);
        assert!(matches!(fed.entities[0], MetadataEntry::Other));
    }

    #[test]
    fn single_entity_descriptor_root_is_promoted_to_aggregate() {
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                     entityID="https://idp.example.com/saml">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="https://idp.example.com/sso"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#,
            cert = rsa_cert_b64()
        );
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities.len(), 1);
        assert!(matches!(fed.entities[0], MetadataEntry::Idp(_)));
    }

    // ---- Endpoint helpers ----

    #[test]
    fn parse_endpoint_handles_index_and_default() {
        let xml = r#"<md:Wrapper xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
            <md:E Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                  Location="https://x/acs" index="3" isDefault="true"/>
            </md:Wrapper>"#;
        let doc = Document::parse(xml.as_bytes()).unwrap();
        let e = doc.root().child_element(Some(MD_NS), "E").unwrap();
        let parsed = parse_endpoint(e).unwrap();
        assert_eq!(parsed.binding, Binding::HttpPost);
        assert_eq!(parsed.url, "https://x/acs");
        assert_eq!(parsed.index, Some(3));
        assert!(parsed.is_default);
    }

    // ---- Signed metadata ----

    /// Sign a metadata document the same way `crate::dsig::verify` tests do.
    fn sign_metadata(target_id: &str, body_xml: &str) -> (String, X509Certificate) {
        let kp = KeyPair::from_pkcs8_pem(RSA_KEY_PKCS8_PEM).unwrap();
        let cert = rsa_cert();
        let c14n_alg = C14nAlgorithm::ExclusiveCanonical;
        let sig_alg = SignatureAlgorithm::RsaSha256;

        let stage_1_xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="{target_id}">{body_xml}</md:EntitiesDescriptor>"#
        );
        let stage_1_doc = Document::parse(stage_1_xml.as_bytes()).unwrap();
        let chain_1 = ancestor_chain(&stage_1_doc, stage_1_doc.root().id()).unwrap();
        let canonical_root =
            canonicalize(&stage_1_doc, stage_1_doc.root(), &chain_1, c14n_alg, &[]).unwrap();
        let reference_digest = DigestAlgorithm::Sha256.digest(&canonical_root);
        let digest_b64 = BASE64_STANDARD.encode(&reference_digest);

        let signed_info_inner = format!(
            r##"<ds:CanonicalizationMethod Algorithm="{c14n}"/><ds:SignatureMethod Algorithm="{sig}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="{c14n}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"##,
            c14n = c14n_alg.uri(),
            sig = sig_alg.uri(),
            id = target_id,
            digest = digest_b64,
        );
        let signed_info_xml = format!(
            r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info_inner}</ds:SignedInfo>"#,
        );
        let signed_info_doc = Document::parse(signed_info_xml.as_bytes()).unwrap();
        let si_chain = ancestor_chain(&signed_info_doc, signed_info_doc.root().id()).unwrap();
        let si_canonical = canonicalize(
            &signed_info_doc,
            signed_info_doc.root(),
            &si_chain,
            c14n_alg,
            &[],
        )
        .unwrap();
        let sig_bytes = kp.sign(sig_alg, &si_canonical).unwrap();
        let sig_b64 = BASE64_STANDARD.encode(&sig_bytes);

        let cert_b64 = cert.to_base64_x509();
        let body = body_xml;
        let si_inner = signed_info_inner.as_str();
        let sig = sig_b64.as_str();
        let cert_text = cert_b64.as_str();
        let final_xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="{target_id}">{body}<ds:Signature><ds:SignedInfo>{si_inner}</ds:SignedInfo><ds:SignatureValue>{sig}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_text}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></md:EntitiesDescriptor>"#,
        );
        (final_xml, cert)
    }

    #[test]
    fn verify_metadata_signature_happy_path() {
        let body = idp_entity_xml("https://idp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);
        verify_metadata_signature(VerifyMetadata {
            metadata_xml: xml.as_bytes(),
            trusted_signing_cert: &cert,
        })
        .expect("signature verifies");
    }

    #[test]
    fn verify_metadata_signature_missing_signature() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {idp}
              </md:EntitiesDescriptor>"#,
            idp = idp_entity_xml("https://idp.example.com/saml")
        );
        let cert = rsa_cert();
        let err = verify_metadata_signature(VerifyMetadata {
            metadata_xml: xml.as_bytes(),
            trusted_signing_cert: &cert,
        })
        .unwrap_err();
        assert!(matches!(err, Error::SignatureMissing));
    }

    #[test]
    fn parse_signed_entities_descriptor_round_trip() {
        let body = idp_entity_xml("https://idp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);
        let fed = parse_signed_entities_descriptor(xml.as_bytes(), &cert).unwrap();
        assert_eq!(fed.entities.len(), 1);
        assert!(fed.find_idp("https://idp.example.com/saml").is_some());
    }

    #[test]
    fn parse_signed_idp_descriptor_via_aggregate() {
        let body = idp_entity_xml("https://idp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);
        let idp = parse_signed_idp_descriptor(xml.as_bytes(), &cert).unwrap();
        assert_eq!(idp.entity_id, "https://idp.example.com/saml");
        let _ = SsoResponseBinding::HttpPost; // import sanity
    }

    #[test]
    fn parse_signed_sp_descriptor_via_aggregate() {
        let body = sp_entity_xml("https://sp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);
        let sp = parse_signed_sp_descriptor(xml.as_bytes(), &cert).unwrap();
        assert_eq!(sp.entity_id, "https://sp.example.com/saml");
    }

    // ---- entityID index ----

    #[test]
    fn by_entity_id_and_index_resolve_all_roles() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {idp}
                {sp}
                {dual}
              </md:EntitiesDescriptor>"#,
            idp = idp_entity_xml("https://idp.example.com/saml"),
            sp = sp_entity_xml("https://sp.example.com/saml"),
            dual = dual_entity_xml("https://shib.example.com/saml"),
        );
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();

        // Linear accessor.
        assert!(matches!(
            fed.by_entity_id("https://idp.example.com/saml"),
            Some(MetadataEntry::Idp(_))
        ));
        assert!(matches!(
            fed.by_entity_id("https://sp.example.com/saml"),
            Some(MetadataEntry::Sp(_))
        ));
        assert!(matches!(
            fed.by_entity_id("https://shib.example.com/saml"),
            Some(MetadataEntry::Dual(_, _))
        ));
        assert!(fed.by_entity_id("nope").is_none());

        // HashMap index returns the same entries.
        let index = fed.index_by_entity_id();
        assert_eq!(index.len(), 3);
        assert!(matches!(
            index.get("https://idp.example.com/saml"),
            Some(MetadataEntry::Idp(_))
        ));
        assert!(matches!(
            index.get("https://shib.example.com/saml"),
            Some(MetadataEntry::Dual(_, _))
        ));
    }

    #[test]
    fn other_entry_has_no_entity_id() {
        let xml = r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
                <md:EntityDescriptor entityID="https://aa.example.com/saml">
                  <md:AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
                </md:EntityDescriptor>
              </md:EntitiesDescriptor>"#;
        let fed = EntitiesDescriptor::from_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(fed.entities[0].entity_id(), None);
        // `Other` entries are skipped by the index.
        assert!(fed.index_by_entity_id().is_empty());
    }

    // ---- streaming parse ----

    #[test]
    fn stream_entities_visits_each_child_lazily() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                       Name="urn:example:federation">
                {idp}
                {sp}
                {dual}
              </md:EntitiesDescriptor>"#,
            idp = idp_entity_xml("https://idp.example.com/saml"),
            sp = sp_entity_xml("https://sp.example.com/saml"),
            dual = dual_entity_xml("https://shib.example.com/saml"),
        );
        let mut ids = Vec::new();
        stream_entities(xml.as_bytes(), |entry| {
            ids.push(entry.entity_id().map(str::to_owned));
            StreamControl::Continue
        })
        .expect("stream ok");
        assert_eq!(
            ids,
            vec![
                Some("https://idp.example.com/saml".to_owned()),
                Some("https://sp.example.com/saml".to_owned()),
                Some("https://shib.example.com/saml".to_owned()),
            ]
        );
    }

    #[test]
    fn stream_entities_stop_short_circuits() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {a}
                {b}
                {c}
              </md:EntitiesDescriptor>"#,
            a = idp_entity_xml("https://a.example.com/saml"),
            b = idp_entity_xml("https://b.example.com/saml"),
            c = idp_entity_xml("https://c.example.com/saml"),
        );
        let mut count = 0usize;
        let mut found = None;
        stream_entities(xml.as_bytes(), |entry| {
            count = count.checked_add(1).unwrap();
            if entry.entity_id() == Some("https://b.example.com/saml") {
                found = entry.entity_id().map(str::to_owned);
                StreamControl::Stop
            } else {
                StreamControl::Continue
            }
        })
        .unwrap();
        assert_eq!(found.as_deref(), Some("https://b.example.com/saml"));
        // Visited a and b only — c was never parsed.
        assert_eq!(count, 2);
    }

    #[test]
    fn stream_entities_flattens_nested_aggregate() {
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                {outer}
                <md:EntitiesDescriptor>
                  {inner}
                </md:EntitiesDescriptor>
              </md:EntitiesDescriptor>"#,
            outer = idp_entity_xml("https://outer.example.com/saml"),
            inner = idp_entity_xml("https://inner.example.com/saml"),
        );
        let mut ids = Vec::new();
        stream_entities(xml.as_bytes(), |entry| {
            ids.push(entry.entity_id().map(str::to_owned));
            StreamControl::Continue
        })
        .unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&Some("https://outer.example.com/saml".to_owned())));
        assert!(ids.contains(&Some("https://inner.example.com/saml".to_owned())));
    }

    #[test]
    fn stream_entities_single_entity_root() {
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                     entityID="https://solo.example.com/saml">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                        Location="https://solo.example.com/sso"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>"#,
            cert = rsa_cert_b64()
        );
        let mut ids = Vec::new();
        stream_entities(xml.as_bytes(), |entry| {
            ids.push(entry.entity_id().map(str::to_owned));
            StreamControl::Continue
        })
        .unwrap();
        assert_eq!(ids, vec![Some("https://solo.example.com/saml".to_owned())]);
    }

    #[test]
    fn stream_entities_entity_containing_entitydescriptor_comment_parses() {
        // A legal comment inside an entity that contains a literal
        // `<md:EntityDescriptor` token must NOT confuse span capture: the
        // entity's real opening `<` is recorded when capture starts, so the
        // comment text is just bytes inside the span, never a new start.
        let xml = r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <md:EntityDescriptor entityID="https://commented.example.com/saml">
                  <!-- spoof: <md:EntityDescriptor entityID="https://evil.example/saml"> -->
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                            Location="https://commented.example.com/sso"/>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
              </md:EntitiesDescriptor>"#;
        let mut ids = Vec::new();
        stream_entities(xml.as_bytes(), |entry| {
            ids.push(entry.entity_id().map(str::to_owned));
            StreamControl::Continue
        })
        .expect("comment-spoof entity must still parse");
        assert_eq!(
            ids,
            vec![Some("https://commented.example.com/saml".to_owned())]
        );
    }

    #[test]
    fn stream_entities_nested_aggregate_inherits_inner_namespace_prefix() {
        // The `ds:` prefix a child relies on is declared on the *inner*
        // EntitiesDescriptor, not the root. The entity builder's seed scope must
        // inherit the inner wrapper's declarations too (RFC-006 §3 nested
        // aggregates), otherwise the child's `ds:KeyInfo` fails to resolve its
        // prefix.
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
                <md:EntitiesDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                  <md:EntityDescriptor entityID="https://nested.example.com/saml">
                    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                      <md:KeyDescriptor use="signing">
                        <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                      </md:KeyDescriptor>
                      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                              Location="https://nested.example.com/sso"/>
                    </md:IDPSSODescriptor>
                  </md:EntityDescriptor>
                </md:EntitiesDescriptor>
              </md:EntitiesDescriptor>"#,
            cert = rsa_cert_b64()
        );
        let mut ids = Vec::new();
        stream_entities(xml.as_bytes(), |entry| {
            ids.push(entry.entity_id().map(str::to_owned));
            StreamControl::Continue
        })
        .expect("nested-namespace entity must parse");
        assert_eq!(
            ids,
            vec![Some("https://nested.example.com/saml".to_owned())]
        );
    }

    #[test]
    fn stream_entities_normalizes_carriage_returns_like_eager_path() {
        // An entity whose certificate text node carries `\r\n` and a bare `\r`.
        // XML 1.0 §2.11 requires both to normalize to `\n` before parsing; the
        // eager DOM path does this in `parse_inner`, and the streaming path must
        // too — otherwise a literal `\r` survives into the entity tree's text
        // node and this crate's c14n escapes it as `&#xD;`, producing a
        // different digest than the eager tree the signer's bytes match.
        let cert = rsa_cert_b64();
        let cert_with_cr = format!("{cert}\r\nTRAILER\rEND");
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><md:EntityDescriptor entityID="https://cr.example.com/saml"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_with_cr}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://cr.example.com/sso"/></md:IDPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor>"#
        );

        // Pull the cert text node out of the eager DOM entity tree.
        let eager_doc = Document::parse(xml.as_bytes()).unwrap();
        let eager_cert_text = eager_doc
            .find_first(Some(DS_NS), "X509Certificate")
            .unwrap()
            .text_content();

        // And out of the streamed entity tree, via the same streaming machinery
        // `stream_entities` uses.
        let mut streamed_cert_text = None;
        stream_entity_elements(xml.as_bytes(), |entity| {
            let text = find_first_in(entity, Some(DS_NS), "X509Certificate")
                .unwrap()
                .text_content();
            streamed_cert_text = Some(text);
            Ok(StreamControl::Continue)
        })
        .expect("stream ok");
        let streamed_cert_text = streamed_cert_text.expect("one entity visited");

        // Both paths normalized `\r\n` and bare `\r` to `\n`, identically.
        assert!(
            !eager_cert_text.contains('\r'),
            "eager path left a carriage return"
        );
        assert!(
            !streamed_cert_text.contains('\r'),
            "streaming path left a carriage return"
        );
        assert!(streamed_cert_text.contains("\nTRAILER\nEND"));
        assert_eq!(
            streamed_cert_text, eager_cert_text,
            "streamed entity text node must match the eager tree byte-for-byte"
        );
    }

    /// Test-only recursive search for the first descendant element with the
    /// given expanded name, mirroring `Document::find_first` but rooted at an
    /// arbitrary [`Element`] (the streamed entity tree has no surrounding
    /// `Document`).
    fn find_first_in<'a>(
        element: &'a Element,
        namespace: Option<&str>,
        local: &str,
    ) -> Option<&'a Element> {
        if element.qname().local() == local && element.qname().namespace() == namespace {
            return Some(element);
        }
        for child in element.child_elements() {
            if let Some(found) = find_first_in(child, namespace, local) {
                return Some(found);
            }
        }
        None
    }

    #[test]
    fn stream_entities_unescapes_seeded_ancestor_namespace_uri() {
        // An ancestor wrapper binds prefix `foo` to a URI containing an XML
        // entity (`&amp;`). A child element inside the entity uses that prefix.
        // The seeded-scope path must unescape the URI to `urn:a&b` exactly as
        // the eager path would for an element's own namespace decls — otherwise
        // the child resolves to the raw `urn:a&amp;b`, diverging from eager.
        let cert = rsa_cert_b64();
        let xml = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><md:EntitiesDescriptor xmlns:foo="urn:a&amp;b"><md:EntityDescriptor entityID="https://esc.example.com/saml"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://esc.example.com/sso"/><foo:Marker/></md:IDPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor></md:EntitiesDescriptor>"#
        );

        // Eager path: the entity tree resolves `foo:Marker` to the unescaped URI.
        let eager_doc = Document::parse(xml.as_bytes()).unwrap();
        let eager_marker_ns = eager_doc
            .find_first(Some("urn:a&b"), "Marker")
            .expect("eager path must resolve foo: to unescaped urn:a&b")
            .qname()
            .namespace()
            .map(str::to_owned);
        assert_eq!(eager_marker_ns.as_deref(), Some("urn:a&b"));

        // Streaming path: the seed scope inherits the inner wrapper's `foo`
        // binding and must unescape it identically.
        let mut streamed_marker_ns = None;
        stream_entity_elements(xml.as_bytes(), |entity| {
            streamed_marker_ns = find_first_in(entity, Some("urn:a&b"), "Marker")
                .map(|m| m.qname().namespace().map(str::to_owned));
            Ok(StreamControl::Continue)
        })
        .expect("stream ok");

        assert_eq!(
            streamed_marker_ns,
            Some(Some("urn:a&b".to_owned())),
            "streamed seed scope must unescape the ancestor URI to match eager"
        );
    }

    #[test]
    fn stream_signed_entities_verifies_before_yield() {
        let body = idp_entity_xml("https://idp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);

        let mut ids = Vec::new();
        stream_signed_entities(xml.as_bytes(), &cert, |entry| {
            ids.push(entry.entity_id().map(str::to_owned));
            StreamControl::Continue
        })
        .expect("verify + stream");
        assert_eq!(ids, vec![Some("https://idp.example.com/saml".to_owned())]);
    }

    #[test]
    fn stream_signed_entities_rejects_bad_signature_without_yielding() {
        let body = idp_entity_xml("https://idp.example.com/saml");
        let (xml, cert) = sign_metadata("md-1", &body);
        let tampered = xml.replacen(
            "https://idp.example.com/sso",
            "https://idp.evil.example/sso",
            1,
        );
        assert_ne!(tampered, xml);

        let mut visited = false;
        let err = stream_signed_entities(tampered.as_bytes(), &cert, |_entry| {
            visited = true;
            StreamControl::Continue
        })
        .unwrap_err();
        assert!(matches!(err, Error::SignatureVerification { .. }));
        assert!(
            !visited,
            "no entity may be yielded from an unverified aggregate"
        );
    }
}
