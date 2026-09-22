"""relay 414 (Axis 2) — WHICH ENFORCEMENT TEST CAN READ THIS EDGE.

⛔ THE DEFECT THIS CLOSES. `device_class` was answering two different questions
at once: *what is this box* AND *is "is it enforcing?" a meaningful question*.
The second was DERIVED from the first via a hardcoded class list
(PROTECTIVE_CLASSES = waf | edge_firewall | adc_lb), mirrored here and in the
portal. That coupling forced a false choice on every managed-hosting edge:

  * call it `waf`  -> it gets verified, but we OVER-CLAIM a configured security
                      policy that does not exist (it is abuse/rate filtering);
  * call it `cdn`  -> honest about what it is, but SILENTLY EXCLUDED from
                      enforcement verification entirely.

Neither is true of Pressable/Automattic. So the two questions are separated:
`device_class` keeps question 1, and THIS module answers question 2.

⭐ THE MECHANISM IS THE ROUTING KEY. This is the stack-aware router in
miniature: an edge is enforcement-relevant iff its mechanism is not `none`, and
the mechanism names WHICH detector can actually read it:

    signature        the 354a/354b differential probe (a benign GET and an
                     attack-signature GET on the same path). Meaningful for a
                     signature-blocking edge — Cloud Armor proved that.
    rate_behavioral  blocks on VOLUME / bot behaviour, not on one injection.
                     The differential cannot test it (relay 405). Today the only
                     detector in this family is 407's FortiWeb bot-challenge;
                     for everything else the honest verdict is
                     "not verified — no applicable detector".
    none             enforcement is not this thing's job. A CDN caches; an
                     origin has nothing in front. Calling either "not enforcing"
                     would misread what it is.

⛔ THIS UN-HARDCODES relay 405. `isRateBasedWaf(/forti/i)` was a MECHANISM
LOOKUP WEARING A VENDOR-REGEX COSTUME, compiled into the portal. It is now a
declared rule read from one table, in one place, in both languages.

⚠ PURE. No I/O, no DB, no registry load. Inputs are the two values every caller
already has: the resolved device_class and the resolved vendor_product.

⚠ MIRROR — relay 352 shape. scripts/scanner/enforcement_mechanism.py and the
portal's src/lib/enforcement-mechanism.mjs implement ONE rule in two languages.
They live in different repos so neither can import the other; what holds them
together is ONE FIXTURE TABLE asserted on both sides (MECHANISM_FIXTURES below
and its .mjs twin), each naming the other file in its failure message. A shared
rule with no shared test is exactly how the digest and the chip came to share
one bug (relay 346/352). Change one side alone and the other suite reds.
"""

MECHANISM_SIGNATURE = "signature"
MECHANISM_RATE = "rate_behavioral"
MECHANISM_NONE = "none"

# Classes where something is demonstrably IN FRONT and could be blocking.
_PROTECTIVE_CLASSES = ("waf", "edge_firewall", "adc_lb")

# A managed-hosting provider's own edge: terminates TLS and actively mediates
# traffic to an origin it also operates. Not a passive cache, not a security
# appliance. Its filtering is abuse/rate protection, so it is rate_behavioral by
# nature — never `signature`, and never rendered "Protected by".
_HOSTING_EDGE_CLASSES = ("hosting_edge",)

# ⛔ VENDORS WHOSE ENFORCEMENT IS RATE/BEHAVIOURAL WHATEVER CLASS THEY LANDED IN.
# Matched as a lowercase substring of "<vendor> <product>".
#
#   forti      — FortiWeb / FortiGate / Fortinet. Blocks on volume and bot
#                detection, not on one injection (relay 405; the vault records a
#                network-level ban of our egress 2026-04-13).
#   automattic — Pressable/Atomic managed WordPress. Silently 403-filters for
#                abuse; that is rate protection, not a configured WAF policy.
#
# ⚠ THE VENDOR TEST RUNS BEFORE THE CLASS TEST ON PURPOSE. A host can be
# MISCLASSIFIED as `waf` and still be rate-based — exactly the live state of the
# www.commandcompanies.com / www.unimacgraphics.com pair, where generic
# presence-only wafw00f ("a WAF is present") outranks the vendor-identifying
# Automattic tell and the dry-run verdict reads `waf`. Keying the mechanism on
# the VENDOR means the wrong class cannot route those hosts into a signature
# test they will silently fail. The class fix is separate (Axis 1) and does not
# have to land first for the verdict to stop over-claiming.
_RATE_BASED_VENDOR_TOKENS = ("forti", "automattic")


def _vendor_haystack(vendor_product) -> str:
    """Flatten a vendor_product into one lowercase haystack.

    ⛔ SHAPE-TOLERANT ON PURPOSE (relay 424, 4.7 finding). This used to accept a
    dict and return "" for everything else — so ('waf', {'vendor':'Automattic'})
    resolved rate_behavioral (safe) while ('waf', 'Automattic'), the bare STRING,
    fell through to `signature` and would have routed a Pressable host into a
    signature probe it cannot answer. The DB stores the dict today, so this was
    latent rather than live, but "safe only for one of the two shapes the
    codebase passes around" is not a property worth relying on — asset_surface,
    the ASM import and hand-built callers all carry vendor as a bare string in
    places. A string is now treated as the vendor name itself.

    Both shapes are in the fixture table, asserted in both languages.
    """
    if isinstance(vendor_product, str):
        return vendor_product.strip().lower()
    if not isinstance(vendor_product, dict):
        return ""
    vendor = vendor_product.get("vendor") or ""
    product = vendor_product.get("product") or ""
    return f"{vendor} {product}".strip().lower()


def is_rate_based_vendor(vendor_product) -> bool:
    """Is this vendor's enforcement rate/behavioural rather than signature-based?"""
    hay = _vendor_haystack(vendor_product)
    if not hay:
        return False
    return any(tok in hay for tok in _RATE_BASED_VENDOR_TOKENS)


def resolve_enforcement_mechanism(device_class, vendor_product=None) -> str:
    """(device_class, vendor_product) -> signature | rate_behavioral | none.

    Rule order is load-bearing and is asserted by the fixture table:
      1. a non-enforcing class is `none` FIRST — a CDN fronted by Automattic is
         still a CDN, and must not be dragged into the population by its vendor.
      2. a rate-based VENDOR is rate_behavioral, even if the class is wrong.
      3. a hosting_edge is rate_behavioral by nature.
      4. anything else left standing is a signature edge.
    """
    cls = (device_class or "").strip().lower()
    if cls not in _PROTECTIVE_CLASSES and cls not in _HOSTING_EDGE_CLASSES:
        return MECHANISM_NONE
    if is_rate_based_vendor(vendor_product):
        return MECHANISM_RATE
    if cls in _HOSTING_EDGE_CLASSES:
        return MECHANISM_RATE
    return MECHANISM_SIGNATURE


def enforcement_applies(device_class, vendor_product=None) -> bool:
    """Is "is it enforcing?" a meaningful question for this edge?

    ⭐ THIS REPLACES THE HARDCODED CLASS LIST. Membership is now DERIVED from the
    mechanism, so adding a class to the taxonomy no longer means editing two
    tuples in two repos and hoping they stay in step.
    """
    return resolve_enforcement_mechanism(device_class, vendor_product) != MECHANISM_NONE


# ── THE SHARED FIXTURE TABLE (relay 352 shape) ──────────────────────────────
# ⛔ THIS TABLE IS DUPLICATED, DELIBERATELY, in the portal's
# src/lib/enforcement-mechanism.mjs. Different repos, so nothing can import
# across them; the pin is THE CASES AND THEIR COUNT asserted on both sides, each
# failure message naming the other file. Edit one without the other and the
# other suite reds.
#
# (device_class, vendor, product, expected_mechanism, why)
MECHANISM_FIXTURES = [
    # ── the enforcement population, by mechanism ──
    ("waf", "Fortinet", "FortiWeb", MECHANISM_RATE,
     "405: the single-signature differential cannot test a rate WAF"),
    ("waf", "Fortinet", "FortiGate", MECHANISM_RATE,
     "same family, same reason"),
    ("waf", "Google Cloud", "Google Cloud Armor", MECHANISM_SIGNATURE,
     "a clean single-signature pass IS meaningful on a signature edge"),
    ("waf", "Cloudflare", "Cloudflare", MECHANISM_SIGNATURE,
     "signature edge"),
    ("waf", None, None, MECHANISM_SIGNATURE,
     "generic presence-only wafw00f, no vendor: treat as a signature edge"),
    ("edge_firewall", None, None, MECHANISM_SIGNATURE,
     "an appliance in front, no rate-based vendor named"),
    ("adc_lb", None, None, MECHANISM_SIGNATURE,
     "a load balancer that could be filtering"),

    # ── the Automattic/Pressable case this relay exists for ──
    ("hosting_edge", "Automattic", None, MECHANISM_RATE,
     "414 Axis 1+2: managed-hosting edge, abuse/rate filtering, NOT a WAF policy"),
    ("waf", "Automattic", None, MECHANISM_RATE,
     "⛔ THE LIVE DRIFT: presence-only wafw00f outranks the Automattic tell and "
     "the class reads `waf`. The VENDOR rule still routes it away from a "
     "signature test, so a wrong class cannot produce a wrong verdict."),
    ("hosting_edge", None, None, MECHANISM_RATE,
     "a hosting edge is rate_behavioral by nature even unattributed"),

    # ── out of the population entirely ──
    ("cdn", "Cloudflare", "Cloudflare", MECHANISM_NONE,
     "a CDN caches; enforcement is not its job"),
    ("cdn", "Automattic", None, MECHANISM_NONE,
     "⛔ RULE ORDER: class-none is decided BEFORE the vendor rule, so a "
     "rate-based vendor cannot drag a CDN into the population"),
    ("origin_host", None, None, MECHANISM_NONE,
     "nothing in front to enforce"),
    ("cloud_endpoint", "Amazon", None, MECHANISM_NONE,
     "hosting, not protection"),
    ("unknown", None, None, MECHANISM_NONE,
     "no classification, no claim"),
    ("unreadable", None, None, MECHANISM_NONE,
     "evidence collection FAILED — no-information, never a verdict"),
    (None, None, None, MECHANISM_NONE,
     "absent class fails closed"),

    # ── (relay 424) VENDOR SHAPE: a bare STRING must resolve like the dict ──
    # 4.7's finding. ('waf', 'Automattic') used to fall through to `signature`
    # while ('waf', {'vendor': 'Automattic'}) resolved rate_behavioral — a
    # Pressable host reached by the string path would have been signature-probed.
    # These four cases pin BOTH shapes against EACH other, so the two can never
    # drift apart again.
    ("waf", "__STR__Automattic", None, MECHANISM_RATE,
     "⛔ bare-string vendor must match the dict shape (424 4.7 finding)"),
    ("waf", "__STR__Fortinet", None, MECHANISM_RATE,
     "same, Fortinet family"),
    ("waf", "__STR__Cloudflare", None, MECHANISM_SIGNATURE,
     "a string that is NOT rate-based stays signature — the fix must not over-match"),
    ("hosting_edge", "__STR__Automattic", None, MECHANISM_RATE,
     "string shape on the hosting edge (was already safe; pinned so it stays)"),
]

# ⚠ FIXTURE ENCODING. A "__STR__" prefix on the vendor field means "pass the
# REST of this value as a BARE STRING vendor_product", not as {"vendor": ...}.
# Encoded rather than given its own column so the table stays one flat shape in
# both languages and the counts keep matching.
STR_SHAPE_PREFIX = "__STR__"


def fixture_vendor_product(vendor, product):
    """Build the vendor_product argument for one fixture row, honouring the
    __STR__ bare-string encoding. Mirrored in the portal's fixtureVendorProduct."""
    if isinstance(vendor, str) and vendor.startswith(STR_SHAPE_PREFIX):
        return vendor[len(STR_SHAPE_PREFIX):]
    if vendor is None and product is None:
        return None
    vp = {}
    if vendor:
        vp["vendor"] = vendor
    if product:
        vp["product"] = product
    return vp
