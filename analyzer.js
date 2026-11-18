const BRANDS = {
  apple: ["apple.com"],
  google: ["google.com"],
  microsoft: ["microsoft.com", "live.com", "office.com"],
  paypal: ["paypal.com"],
  amazon: ["amazon.com"],
  netflix: ["netflix.com"],
};

const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly"]);
const DOWNLOAD_EXTENSIONS = /\.(exe|scr|msi|dmg|pkg|apk|iso|zip)$/i;

function isIpv4(host) {
  const parts = host.split(".");
  return parts.length === 4 && parts.every(part => /^\d+$/.test(part) && Number(part) <= 255);
}

function isIpv6(host) {
  return host.includes(":") && /^[0-9a-f:]+$/i.test(host.replace(/^\[|\]$/g, ""));
}

function officialForBrand(host, allowed) {
  return allowed.some(domain => host === domain || host.endsWith(`.${domain}`));
}

function registrableApproximation(host) {
  const labels = host.split(".").filter(Boolean);
  return labels.length >= 2 ? labels.slice(-2).join(".") : host;
}

export function analyzeUrl(rawInput) {
  const input = String(rawInput || "").trim();
  if (!input) throw new Error("Enter a URL to analyze.");
  if (input.length > 2048) throw new Error("The URL is longer than the 2,048-character safety limit.");

  let parsed;
  try { parsed = new URL(input); } catch { throw new Error("Enter a complete URL beginning with http:// or https://."); }
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS URLs can be assessed.");

  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const findings = [];
  const facts = [];
  let score = 0;
  const add = (points, severity, title, explanation, evidence) => {
    score += points;
    findings.push({points, severity, title, explanation, evidence});
  };

  facts.push({label:"Parsed host", value:host});
  facts.push({label:"Declared scheme", value:parsed.protocol.slice(0,-1).toUpperCase()});
  if (parsed.protocol === "http:") add(24, "high", "Unencrypted HTTP is declared", "The address does not request HTTPS. Data could be exposed or modified in transit.", "Scheme is http://");
  else facts.push({label:"HTTPS declaration", value:"Present; certificate not verified"});

  if (parsed.username || parsed.password) add(30, "critical", "Credentials are embedded before the host", "Text before an @ symbol can make the real destination harder to notice.", `Actual host: ${host}`);
  if (isIpv4(host) || isIpv6(host)) add(24, "high", "The destination is an IP address", "Legitimate services can use IP addresses, but sign-in links usually use a recognizable domain.", host);
  if (host.includes("xn--")) add(28, "critical", "Punycode appears in the host", "Punycode can represent legitimate internationalized domains or visually confusing characters.", host);
  if (/[^\x00-\x7F]/.test(input)) add(18, "high", "Non-ASCII characters appear in the URL", "International characters may be legitimate, but lookalike characters deserve careful manual review.", "Unicode characters detected");

  const labels = host.split(".").filter(Boolean);
  if (labels.length > 4) add(12, "medium", "Many subdomain levels", "Attackers sometimes place trusted words far to the left of the actual registered domain.", `${labels.length} host labels`);
  if (host.length > 60) add(10, "medium", "Long hostname", "A long host can hide the meaningful domain label in narrow displays.", `${host.length} characters`);
  if (parsed.port && !["80", "443"].includes(parsed.port)) add(10, "medium", "Unusual explicit port", "An explicit nonstandard port is not automatically harmful but changes where the browser connects.", `Port ${parsed.port}`);
  if (SHORTENERS.has(host)) add(14, "medium", "URL-shortening service", "The visible address hides the final destination. Expand it only with a trusted, non-navigating service.", host);

  const approximateDomain = registrableApproximation(host);
  for (const [brand, allowed] of Object.entries(BRANDS)) {
    if (host.includes(brand) && !officialForBrand(host, allowed)) {
      add(34, "critical", "Possible brand impersonation pattern", `The host contains “${brand}” but the approximate destination is ${approximateDomain}, not a listed official domain. This is a heuristic, not brand verification.`, host);
      break;
    }
  }

  const percentCount = (input.match(/%[0-9a-f]{2}/gi) || []).length;
  if (percentCount >= 4) add(10, "medium", "Heavy percent-encoding", "Encoded characters can be normal, but extensive encoding makes a URL harder to inspect.", `${percentCount} encoded bytes`);
  if (input.length > 140) add(7, "low", "Long overall URL", "Long query strings are common in tracking and applications, but they reduce readability.", `${input.length} characters`);
  if (DOWNLOAD_EXTENSIONS.test(parsed.pathname)) add(18, "high", "Executable or archive-like path", "Unexpected downloads deserve separate verification before opening.", parsed.pathname.split("/").pop());
  if (parsed.hash && /access_token|password|session/i.test(parsed.hash)) add(12, "medium", "Sensitive-looking fragment name", "The fragment contains a term associated with credentials or sessions. Do not share the URL.", parsed.hash.slice(0,80));

  score = Math.min(100, score);
  findings.sort((a,b) => b.points - a.points);
  const label = score >= 70 ? "High review priority" : score >= 35 ? "Caution advised" : score > 0 ? "Some warning signals" : "No structural warning found";
  const recommendation = score >= 70
    ? "Do not open the link. Navigate independently using a trusted bookmark or manually typed official address, then contact the sender through another channel."
    : score >= 35
      ? "Pause before opening. Confirm the real host from right to left and verify the sender independently."
      : "No major structural warning was found, but structure alone cannot establish safety. Verify context and destination independently.";
  return {
    score, label, host, scheme: parsed.protocol.slice(0,-1).toUpperCase(), approximateDomain,
    findings, facts, recommendation,
    verifiedStatement:"Only the supplied text was parsed. No DNS, certificate, availability, ownership, or reputation check was performed.",
  };
}
