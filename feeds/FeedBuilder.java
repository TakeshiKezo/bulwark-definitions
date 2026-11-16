import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bulwark definitions feed builder (JDK 17+, no dependencies).
 *
 *   java server/feeds/FeedBuilder.java \
 *        --sources server/feeds/sources.json \
 *        --base    app/src/main/assets/defs \
 *        --out     server/public/v1 \
 *        --key     tools/keys            (folder with defs_private.pk8)
 *        [--version 2026.11.16.1] [--offline]
 *
 * 1. Downloads every source from sources.json (optional auth key from environment variables)
 * 2. Merges with the curated base set (rules.yar, trusted_certs.txt, own hashes/domains)
 * 3. Validates, de-duplicates, applies size limits and a sanity check (no feed may shrink
 *    the set by more than 50 % compared to the previous build - protects against broken feeds)
 * 4. Writes the 4 definition files + manifest.json and signs it (ECDSA P-256, manifest.sig)
 *
 * The output folder can be served by ANY static HTTPS host (nginx, GitHub Pages, S3/CloudFront ...).
 */
public class FeedBuilder {
    static final Pattern SHA256 = Pattern.compile("^[0-9a-fA-F]{64}$");
    static final Pattern DOMAIN = Pattern.compile("^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z][a-z0-9-]{1,62}$");
    static final String[] FILES = {"hash_blocklist.txt", "rules.yar", "phishing_domains.txt", "trusted_certs.txt"};

    public static void main(String[] args) throws Exception {
        Map<String, String> a = parseArgs(args);
        Path sources = Paths.get(a.getOrDefault("sources", "server/feeds/sources.json"));
        Path base = Paths.get(a.getOrDefault("base", "app/src/main/assets/defs"));
        Path out = Paths.get(a.getOrDefault("out", "server/public/v1"));
        Path key = a.containsKey("key") ? Paths.get(a.get("key")) : null;
        boolean offline = a.containsKey("offline");
        String version = a.getOrDefault("version", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy.MM.dd.HHmm")));

        String json = Files.readString(sources);
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).followRedirects(HttpClient.Redirect.NORMAL).build();

        // ---- hashes
        LinkedHashMap<String, String> hashes = new LinkedHashMap<>();
        readHashLines(Files.readString(base.resolve("hash_blocklist.txt")), hashes, null);
        int baseHashes = hashes.size();
        for (Map<String, String> src : sourceList(json, "hashes")) {
            if (offline) break;
            String body = fetch(http, src);
            if (body == null) continue;
            int before = hashes.size();
            if ("bazaar-csv".equals(src.get("format"))) readBazaarCsv(body, hashes);
            else readHashLines(body, hashes, src.getOrDefault("label", "Feed"));
            log("hashes  +" + (hashes.size() - before) + "  " + src.get("name"));
        }

        // ---- domains
        LinkedHashSet<String> domains = new LinkedHashSet<>();
        readDomains(Files.readString(base.resolve("phishing_domains.txt")), "domains", domains);
        for (Map<String, String> src : sourceList(json, "domains")) {
            if (offline) break;
            String body = fetch(http, src);
            if (body == null) continue;
            int before = domains.size();
            readDomains(body, src.get("format"), domains);
            log("domains +" + (domains.size() - before) + "  " + src.get("name"));
        }

        int maxHashes = intLimit(json, "maxHashes", 400000);
        int maxDomains = intLimit(json, "maxDomains", 300000);

        // ---- sanity checks: never publish a degraded set (devices would silently lose protection)
        if (!failedSources.isEmpty() && !a.containsKey("allow-partial")) {
            throw new IllegalStateException("source(s) unavailable: " + failedSources
                    + " - keeping the last published set (use --allow-partial to override)");
        }
        checkShrink(out.resolve("hash_blocklist.txt"), hashes.size(), "hash", offline);
        checkShrink(out.resolve("phishing_domains.txt"), domains.size(), "domain", offline);

        // ---- write
        Files.createDirectories(out);
        StringBuilder hb = new StringBuilder("# Bulwark hash blocklist " + version + "\n# Format: <sha256>;<file|cert>;<name>\n");
        hashes.entrySet().stream().limit(maxHashes).forEach(e -> hb.append(e.getKey()).append(';').append(e.getValue()).append('\n'));
        Files.writeString(out.resolve("hash_blocklist.txt"), hb.toString());

        StringBuilder db = new StringBuilder("# Bulwark phishing/malware domains " + version + "\n");
        domains.stream().limit(maxDomains).forEach(d -> db.append(d).append('\n'));
        Files.writeString(out.resolve("phishing_domains.txt"), db.toString());

        Files.copy(base.resolve("rules.yar"), out.resolve("rules.yar"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(base.resolve("trusted_certs.txt"), out.resolve("trusted_certs.txt"), StandardCopyOption.REPLACE_EXISTING);

        String manifest = manifest(out, version);
        Files.writeString(out.resolve("manifest.json"), manifest);
        if (key != null) {
            Files.writeString(out.resolve("manifest.sig"), sign(manifest, key.resolve("defs_private.pk8")));
            log("manifest signed");
        } else {
            log("WARNING: no --key given, manifest.sig not written (the app will reject this set)");
        }
        log("done: version " + version + ", " + Math.min(hashes.size(), maxHashes) + " hashes (" + baseHashes + " curated), "
                + Math.min(domains.size(), maxDomains) + " domains -> " + out.toAbsolutePath());
    }

    static final List<String> failedSources = new ArrayList<>();

    static void checkShrink(Path previous, int now, String what, boolean offline) throws IOException {
        if (!Files.exists(previous) || offline) return;
        long prev = Files.readAllLines(previous).stream().filter(l -> !l.startsWith("#") && !l.isBlank()).count();
        if (prev > 1000 && now < prev / 2) {
            throw new IllegalStateException(what + " count dropped from " + prev + " to " + now + " - refusing to publish");
        }
    }

    // ------------------------------------------------------------------ parsing

    /** MalwareBazaar CSV: first_seen, sha256, md5, sha1, reporter, file_name, file_type, mime, signature, ... */
    static void readBazaarCsv(String text, Map<String, String> out) {
        for (String raw : text.split("\\R")) {
            if (raw.isBlank() || raw.startsWith("#")) continue;
            String[] c = raw.split("\",\\s*\"");
            if (c.length < 9) continue;
            String sha = c[1].replace("\"", "").trim().toLowerCase(Locale.ROOT);
            if (!SHA256.matcher(sha).matches()) continue;
            String sig = c[8].replace("\"", "").trim();
            String type = c[6].replace("\"", "").trim();
            String family = (sig.isEmpty() || sig.equals("n/a")) ? "Generic." + (type.isEmpty() ? "bin" : type) : sig;
            out.putIfAbsent(sha, "file;MalwareBazaar." + family.replaceAll("[^A-Za-z0-9._-]", "_"));
        }
    }

    static void readHashLines(String text, Map<String, String> out, String label) {
        for (String raw : text.split("\\R")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] p = line.split(";", 3);
            String h = p[0].trim().toLowerCase(Locale.ROOT);
            if (!SHA256.matcher(h).matches()) continue;
            if (p.length == 3) out.putIfAbsent(h, p[1].trim() + ";" + p[2].trim());
            else out.putIfAbsent(h, "file;" + label + ".Malware");
        }
    }

    static void readDomains(String text, String format, Set<String> out) {
        for (String raw : text.split("\\R")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) continue;
            String host;
            switch (format == null ? "domains" : format) {
                case "hosts" -> {
                    String[] p = line.split("\\s+");
                    host = p.length >= 2 ? p[1] : p[0];
                }
                case "urls" -> {
                    try { host = URI.create(line.replace(" ", "%20")).getHost(); } catch (Exception e) { host = null; }
                }
                default -> host = line.split("[\\s#]")[0];
            }
            if (host == null) continue;
            host = host.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
            if (host.equals("localhost") || !DOMAIN.matcher(host).matches()) continue;
            out.add(host);
        }
    }

    // ------------------------------------------------------------------ network

    /** Primary URL, then optional "mirror", 2 attempts each; a source that fails completely is recorded. */
    static String fetch(HttpClient http, Map<String, String> src) {
        for (String url : new String[]{src.get("url"), src.get("mirror")}) {
            if (url == null) continue;
            for (int attempt = 1; attempt <= 2; attempt++) {
                String body = fetchOnce(http, src, url);
                if (body != null && !body.isBlank()) return body;
            }
        }
        if ("true".equals(src.get("optional"))) log("optional source unavailable: " + src.get("name"));
        else failedSources.add(src.get("name"));
        return null;
    }

    static String fetchOnce(HttpClient http, Map<String, String> src, String url) {
        try {
            String env0 = src.get("authEnv");
            if (url.contains("%AUTH%")) {
                String key = env0 == null ? null : System.getenv(env0);
                if (key == null || key.isBlank()) { log("skip (env " + env0 + " not set)  " + src.get("name")); return null; }
                url = url.replace("%AUTH%", key);
            }
            HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(120)).header("User-Agent", "Bulwark-FeedBuilder/1.0");
            String env = src.get("authEnv");
            if (env != null && System.getenv(env) != null && src.get("authHeader") != null) {
                rb.header(src.get("authHeader"), System.getenv(env));
            }
            HttpResponse<String> r = http.send(rb.GET().build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (r.statusCode() != 200) {
                log("skip (HTTP " + r.statusCode() + ")  " + src.get("name") + (env != null && (r.statusCode() == 401 || r.statusCode() == 403 || r.statusCode() == 410) ? "  -> free key: https://auth.abuse.ch, then set env " + env : ""));
                return null;
            }
            return r.body();
        } catch (IOException | InterruptedException | IllegalArgumentException e) {
            log("skip (" + e.getClass().getSimpleName() + ")  " + src.get("name"));
            return null;
        }
    }

    // ------------------------------------------------------------------ manifest & signing

    static String manifest(Path dir, String version) throws Exception {
        StringBuilder files = new StringBuilder();
        for (int i = 0; i < FILES.length; i++) {
            byte[] data = Files.readAllBytes(dir.resolve(FILES[i]));
            files.append(i == 0 ? "" : ",").append("\n    \"").append(FILES[i]).append("\": \"").append(hex(MessageDigest.getInstance("SHA-256").digest(data))).append('"');
        }
        return "{\n  \"version\": \"" + version + "\",\n  \"releasedAt\": " + System.currentTimeMillis()
                + ",\n  \"minAppVersion\": 1,\n  \"files\": {" + files + "\n  }\n}\n";
    }

    static String sign(String manifest, Path pk8) throws Exception {
        PrivateKey pk = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(pk8)));
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(pk);
        s.update(manifest.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    // ------------------------------------------------------------------ tiny helpers (no JSON lib)

    /** Extracts the objects of a top-level array in sources.json (flat string fields only). */
    static List<Map<String, String>> sourceList(String json, String key) {
        List<Map<String, String>> list = new ArrayList<>();
        int start = json.indexOf("\"" + key + "\"");
        if (start < 0) return list;
        int open = json.indexOf('[', start);
        int depth = 0, end = open;
        for (int i = open; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '[') depth++;
            if (c == ']' && --depth == 0) { end = i; break; }
        }
        Matcher obj = Pattern.compile("\\{([^{}]*)}").matcher(json.substring(open, end));
        Pattern kv = Pattern.compile("\"(\\w+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        while (obj.find()) {
            Map<String, String> m = new HashMap<>();
            Matcher f = kv.matcher(obj.group(1));
            while (f.find()) m.put(f.group(1), f.group(2));
            if (!"false".equalsIgnoreCase(m.get("enabled"))) list.add(m); else log("disabled (license)  " + m.get("name"));
        }
        return list;
    }

    static int intLimit(String json, String key, int def) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : def;
    }

    static Map<String, String> parseArgs(String[] args) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--")) continue;
            String k = args[i].substring(2);
            if (i + 1 < args.length && !args[i + 1].startsWith("--")) m.put(k, args[++i]); else m.put(k, "true");
        }
        return m;
    }

    static String hex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x)); return sb.toString(); }
    static void log(String s) { System.out.println("[feed] " + s); }
}
