// Store the freshly analyzed Program in REA's analysis cache before the bridge
// serves it, so a later session for the same target and profile imports this
// packed database with -noanalysis instead of repeating import and analysis.
// Runs after the post-analysis repair scripts. Failures never fail the session.
//@category REA

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;

public class ReaGhidraSaveAnalysis extends GhidraScript {

    private static final String FORMAT = "rea-ghidra-analysis-cache-v1";

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 3)
            throw new IllegalArgumentException("REA analysis cache requires directory, key and run id");
        Path directory = Path.of(arguments[0]);
        String key = arguments[1];
        String runId = arguments[2];
        if (!key.matches("[a-f0-9]{64}") || !runId.matches("[A-Za-z0-9-]{1,64}"))
            throw new IllegalArgumentException("REA analysis cache key is invalid");
        // GhidraScript wraps run() in a transaction; packing needs none open.
        end(true);
        Path partial = directory.resolve(key + "." + runId + ".partial");
        try {
            Files.createDirectories(directory);
            long started = System.nanoTime();
            currentProgram.saveToPackedFile(partial.toFile(), monitor);
            String digest = sha256(partial);
            long bytes = Files.size(partial);
            move(partial, directory.resolve(key + ".gzf"));
            JsonObject manifest = new JsonObject();
            manifest.addProperty("format", FORMAT);
            manifest.addProperty("key", key);
            manifest.addProperty("sha256", digest);
            manifest.addProperty("bytes", bytes);
            manifest.addProperty("program_name", currentProgram.getName());
            manifest.addProperty("created_at", Instant.now().toString());
            // The manifest is the commit marker: readers trust only a .gzf
            // whose digest matches the manifest written after it.
            Path pendingManifest = directory.resolve(key + "." + runId + ".manifest.partial");
            Files.writeString(pendingManifest, manifest + "\n", StandardCharsets.UTF_8);
            move(pendingManifest, directory.resolve(key + ".json"));
            println(String.format(
                "REA analysis cache stored %d bytes in %d ms",
                bytes,
                (System.nanoTime() - started) / 1_000_000
            ));
        }
        catch (Exception exception) {
            Files.deleteIfExists(partial);
            println("REA analysis cache store skipped: " + exception.getClass().getSimpleName() +
                ": " + exception.getMessage());
        }
    }

    private static void move(Path source, Path target) throws Exception {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }
        catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[1 << 16];
        try (InputStream input = Files.newInputStream(path)) {
            for (int read; (read = input.read(buffer)) > 0;) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
