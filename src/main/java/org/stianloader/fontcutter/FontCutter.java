package org.stianloader.fontcutter;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stianloader.picoresolve.version.MavenVersion;

import xmlparser.XmlParser;
import xmlparser.model.XmlElement;

import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.util.PathConverter;
import joptsimple.util.PathProperties;

public class FontCutter {

    private static final char[] CHAR_LOOKUP = new char[]{
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private static void deploy(@NotNull HttpClient client, @NotNull URI remoteURI, Map<GAVCE, Map.Entry<FontFile, DigestValues>> deploymentFiles) {
        record GA(@NotNull String group, @NotNull String artifactId) { }

        Map<GA, String> deployedGAs = new LinkedHashMap<>();

        for (Map.Entry<GAVCE, Map.Entry<FontFile, DigestValues>> e : deploymentFiles.entrySet()) {
            GAVCE gavce = e.getKey();

            URI parentPath = remoteURI.resolve(gavce.group().replace('.', '/') + "/" + gavce.artifactId() + "/" + gavce.version() + "/");

            String baseName = gavce.artifactId() + "-" + gavce.version();
            if (gavce.classifier() != null) {
                baseName += "-" + gavce.classifier();
            }
            baseName += "." + gavce.extension();

            DigestValues digests = Objects.requireNonNull(e.getValue().getValue());

            try {
                FontCutter.upload(client, parentPath, baseName, digests, BodyPublishers.ofFile(e.getValue().getKey().path()));
            } catch (FileNotFoundException e1) {
                throw new AssertionError(e1);
            }

            String prevVersion = deployedGAs.putIfAbsent(new GA(gavce.group(), gavce.artifactId()), gavce.version());

            if (prevVersion != null && !gavce.version().equals(prevVersion)) {
                throw new IllegalStateException("Deploying multiple versions of GA pair");
            }
        }

        // update A-level metadata
        for (Map.Entry<GA, String> deployedVersion : deployedGAs.entrySet()) {
            GA ga = deployedVersion.getKey();
            String version = Objects.requireNonNull(deployedVersion.getValue(), "version is null");

            URI resolvedURIparent = remoteURI.resolve(ga.group().replace('.', '/') + "/" + ga.artifactId() + "/");
            URI resolvedURI = resolvedURIparent.resolve("maven-metadata.xml");

            XmlElement mavenMetadata;

            readMetadata:
            try {
                HttpResponse<String> response = client.send(HttpRequest.newBuilder(resolvedURI).build(), BodyHandlers.ofString());

                if (response.statusCode() == 404) {
                    mavenMetadata = new XmlElement(null, "metadata", new HashMap<>());
                    XmlElement groupId = new XmlElement(mavenMetadata, "groupId", new HashMap<>());
                    groupId.setText(ga.group());
                    mavenMetadata.appendChild(groupId);
                    XmlElement artifactId = new XmlElement(mavenMetadata, "artifactId", new HashMap<>());
                    artifactId.setText(ga.artifactId());
                    mavenMetadata.appendChild(artifactId);
                    XmlElement versioning = new XmlElement(mavenMetadata, "versioning", new HashMap<>());
                    mavenMetadata.appendChild(versioning);
                    XmlElement latest = new XmlElement(versioning, "latest", new HashMap<>());
                    latest.setText("0");
                    versioning.appendChild(latest);
                    XmlElement release = new XmlElement(versioning, "release", new HashMap<>());
                    release.setText("0");
                    versioning.appendChild(release);
                    XmlElement versions = new XmlElement(versioning, "versions", new HashMap<>());
                    versioning.appendChild(versions);
                    XmlElement lastUpdated = new XmlElement(versioning, "lastUpdated", new HashMap<>());
                    lastUpdated.setText("0");
                    versioning.appendChild(lastUpdated);
                    break readMetadata;
                } else if (response.statusCode() != 200) {
                    LoggerFactory.getLogger(FontCutter.class).warn("Recieved status code {} for URI {}", response.statusCode(), resolvedURI);
                } else {
                    // TODO verify checksums of downloaded document
                }

                mavenMetadata = XmlParser.newXmlParser().build().fromXml(response.body());
            } catch (IOException | InterruptedException e) {
                LoggerFactory.getLogger(FontCutter.class).error("IO exception whilst performing HTTP requests", e);
                throw new AssertionError(e);
            }

            XmlElement versioning = mavenMetadata.findChildForName("versioning", null);

            if (versioning == null) {
                throw new IllegalStateException("Invalid XML (versioning == null) for URI " + resolvedURI);
            }

            XmlElement latest = versioning.findChildForName("latest", null);
            XmlElement release = versioning.findChildForName("release", null);
            XmlElement lastUpdated = versioning.findChildForName("lastUpdated", null);
            XmlElement versions = versioning.findChildForName("versions", null);

            if (latest == null) {
                throw new IllegalStateException("Invalid XML (latest == null) for URI " + resolvedURI);
            } else if (release == null) {
                throw new IllegalStateException("Invalid XML (release == null) for URI " + resolvedURI);
            } else if (lastUpdated == null ) {
                throw new IllegalStateException("Invalid XML (lastUpdated == null) for URI " + resolvedURI);
            } else if (versions == null ) {
                throw new IllegalStateException("Invalid XML (versions == null) for URI " + resolvedURI);
            }

            LocalDateTime time = LocalDateTime.now(Clock.systemUTC());
            lastUpdated.setText(time.getYear()
                    + ""
                    + time.getMonthValue()
                    + time.getDayOfMonth()
                    + time.getHour()
                    + time.getMinute()
                    + time.getSecond());
            release.setText(version);
            latest.setText(version);

            XmlElement xmlversion = new XmlElement(versions, "version", new HashMap<>());
            xmlversion.setText(version);
            versions.appendChild(xmlversion);

            byte[] uploadData = XmlParser.newXmlParser().shouldEncodeUTF8(true).shouldPrettyPrint(true).escapeXml().charset(StandardCharsets.UTF_8).build().domToXml(mavenMetadata).getBytes(StandardCharsets.UTF_8);
            if (uploadData == null) {
                throw new AssertionError();
            }
            DigestValues metadataDigests = FontCutter.loadHashes(uploadData);

            FontCutter.upload(client, resolvedURIparent, "maven-metadata.xml", metadataDigests, BodyPublishers.ofByteArray(uploadData));
        }
    }

    @Nullable
    public static MavenVersion getLatestVersion(@NotNull HttpClient client, @NotNull URI remoteURI, @NotNull GAVCE gavce) {
        LoggerFactory.getLogger(FontCutter.class).info("Fetching maven-metadata.xml for {}:{}", gavce.group(), gavce.artifactId());
        URI resolvedURI = remoteURI.resolve(gavce.group().replace('.', '/') + "/" + gavce.artifactId() + "/" + "maven-metadata.xml");

        try {
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(resolvedURI).build(), BodyHandlers.ofString());

            if (response.statusCode() == 404) {
                return null;
            } else if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Recieved status code {} for URI {}", response.statusCode(), resolvedURI);
            }

            XmlElement mavenMetadata = XmlParser.newXmlParser().build().fromXml(response.body());
            List<XmlElement> elements = mavenMetadata.getElementsByTagName("version");
            MavenVersion mostRecent = null;
            for (XmlElement element : elements) {
                String text = Objects.requireNonNull(element.getText());
                MavenVersion parsed = MavenVersion.parse(text);
                if (mostRecent == null || parsed.isNewerThan(mostRecent)) {
                    mostRecent = parsed;
                }
            }

            return mostRecent;
        } catch (IOException | InterruptedException e) {
            LoggerFactory.getLogger(FontCutter.class).error("IO exception whilst performing HTTP requests", e);
            throw new AssertionError(e);
        }
    }

    @NotNull
    private static String getVersion(@NotNull Path basePath) throws IOException {
        Path propertiesPath = basePath.resolve("gradle.properties");
        Properties props = new Properties();

        try (BufferedReader reader = Files.newBufferedReader(propertiesPath, StandardCharsets.UTF_8)) {
            props.load(reader);
        }

        String appVersion = props.getProperty("appVersion");

        if (appVersion == null) {
            throw new IOException("Property 'appVersion' not found in properties file " + propertiesPath);
        }

        String suffix = "-SNAPSHOT";

        if (appVersion.endsWith(suffix)) {
            appVersion = appVersion.substring(0, appVersion.length() - suffix.length());
        }

        return appVersion;
    }

    @NotNull
    private static DigestValues loadHashes(byte @NotNull[] data) {
        try {
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            MessageDigest md5 = MessageDigest.getInstance("MD5");

            byte[] sha512Digest = sha512.digest(data);
            byte[] sha256Digest = sha256.digest(data);
            byte[] sha1Digest = sha1.digest(data);
            byte[] md5Digest = md5.digest(data);

            return new DigestValues(FontCutter.toHex(md5Digest), FontCutter.toHex(sha1Digest), FontCutter.toHex(sha256Digest), FontCutter.toHex(sha512Digest));
        } catch (NoSuchAlgorithmException e) {
            LoggerFactory.getLogger(FontCutter.class).error("Unable to hash files - missing digest", e);
            throw new AssertionError(e);
        }
    }

    @NotNull
    private static DigestValues loadHashes(@NotNull Path file) {
        try {
            return FontCutter.loadHashes(Files.readAllBytes(file));
        } catch (IOException e) {
            LoggerFactory.getLogger(FontCutter.class).error("Unable to hash files - unable to read file '{}'", file, e);
            throw new AssertionError(e);
        }
    }

    public static void main(String[] args) {
        URI remoteURI;
        Path repositoryPath;
        String groupId;

        // Parse arguments
        {
            OptionParser parser = new OptionParser(true);

            OptionSpec<@NotNull URI> remoteURISpec = parser.accepts("remoteURI", "Deployment target URI")
                .withRequiredArg()
                .required()
                .withValuesConvertedBy(URIDirectoryConverter.INSTANCE);

            OptionSpec<Path> repositoryPathSpec = parser.accepts("repository", "Fontwriter repository path")
                    .withRequiredArg()
                    .defaultsTo(".")
                    .withValuesConvertedBy(new PathConverter(PathProperties.DIRECTORY_EXISTING));

            OptionSpec<@NotNull String> groupIdSpec = parser.accepts("groupId", "Deployment group ID")
                    .withRequiredArg()
                    .defaultsTo("org.stianloader.fonts")
                    .ofType(String.class);

            OptionSet options = parser.parse(args);

            remoteURI = options.valueOf(remoteURISpec);
            repositoryPath = options.valueOf(repositoryPathSpec);
            groupId = options.valueOf(groupIdSpec);
        }

        Path path = repositoryPath.resolve("docs", "knownFonts");
        Logger logger = LoggerFactory.getLogger(FontCutter.class);

        if (Files.notExists(path)) {
            logger.error("Path to repository '{}' is invalid. Directory '{}' does not exist!", repositoryPath, path);
            throw new AssertionError();
        } else if (!Files.isDirectory(path)) {
            logger.error("Path to known fonts directory '{}' does not point to a path!", path);
            throw new AssertionError();
        }

        String version;

        try {
            version = FontCutter.getVersion(repositoryPath);
        } catch (IOException e) {
            logger.error("Cannot extract version from repository at '{}'!", repositoryPath, e);
            throw new AssertionError();
        }

        logger.info("Version {} is being used as the content source for the FontCutter application", version);

        Map<FontACE, List<FontFile>> fontFiles;
        try {
            fontFiles = Files.list(path)
                .filter(Files::isRegularFile)
                .map(p -> {
                    String fileName = p.getFileName().toString();
                    int dotIndex = fileName.indexOf('.');
                    String extension = fileName.substring(dotIndex + 1);
                    int dashIndex = fileName.lastIndexOf('-', dotIndex);
                    String classifier = fileName.substring(dashIndex + 1, dotIndex);
                    String name = fileName.substring(0, dashIndex);
                    return new FontFile(name, classifier, extension, p);
                })
                .collect(new SubvalueBinner<>(FontFile::getACE));
        } catch (IOException e) {
            logger.error("A generic IO error occured whilst enumerating font files! What could it be? Just read the attached stacktrace I guess.", e);
            throw new AssertionError();
        }

        for (Map.Entry<FontACE, List<FontFile>> entry : fontFiles.entrySet()) {
            if (entry.getValue().size() != 1) {
                logger.error("ACE {} maps to multiple files: {}.", entry.getKey(), entry.getValue());
                throw new AssertionError();
            }
        }

        Map<FontACE, FontFile> files = new LinkedHashMap<>();
        Map<FontACE, FontFile> licenseFiles = new LinkedHashMap<>();
        Map<FontACE, FontFile> deployableFiles = new LinkedHashMap<>();

        fontFiles.forEach((ace, list) -> {
            files.put(ace, list.get(0));
        });

        files.forEach((ace, file) -> {
            String artifactId = ace.artifactId();
            while (!artifactId.isEmpty()) {
                FontACE licenseACE = new FontACE(artifactId, "License", "txt");
                FontFile licenseFile = files.get(licenseACE);
                if (licenseFile == null) {
                    licenseACE = new FontACE(artifactId, "License", "md");
                    licenseFile = files.get(licenseACE);
                }
                if (licenseFile != null) {
                    if (!licenseACE.equals(ace)) {
                        deployableFiles.put(ace, file);
                    }
                    licenseFiles.put(ace, licenseFile);
                    return;
                }
                int dashIndex = artifactId.lastIndexOf('-');
                if (dashIndex < 0) {
                    break;
                }
                artifactId = artifactId.substring(0, dashIndex);
            }
            files.forEach((a, x) -> {
                System.out.println(a + "-->" + x);
            });
            logger.error("File {} with coordinates {} has no license file attached", ace, file);
            throw new AssertionError();
        });

        AtomicReference<String> deploymentArtifactId = new AtomicReference<>("");
        Map<GAVCE, Map.Entry<FontFile, DigestValues>> deploymentFiles = new HashMap<>();
        AtomicBoolean requireDeployment = new AtomicBoolean();
        AtomicReference<MavenVersion> latestVersion = new AtomicReference<>(null);

        HttpClient client = Objects.requireNonNull(HttpClient.newHttpClient());

        deployableFiles.forEach((ace, fontFile) -> {
            GAVCE gavce = new GAVCE(groupId, ace.artifactId(), version, ace.classifier(), ace.extension());
            DigestValues digest = FontCutter.loadHashes(fontFile.path());

            if (!ace.artifactId().equals(deploymentArtifactId.getPlain())) {
                if (requireDeployment.getPlain()) {
                    FontCutter.deploy(Objects.requireNonNull(client), remoteURI, deploymentFiles);
                }
                deploymentFiles.clear();
                deploymentArtifactId.setPlain(ace.artifactId());
                requireDeployment.setPlain(false);
                latestVersion.setPlain(FontCutter.getLatestVersion(client, remoteURI, gavce));
            }

            deploymentFiles.put(gavce, Map.entry(fontFile, digest));

            if (!requireDeployment.getPlain() && !FontCutter.satisfiesHashes(client, remoteURI, gavce, digest)) {
                requireDeployment.setPlain(true);
            }
        });

        client.close();
    }

    @NotNull
    private static Optional<Boolean> satisfiesHash(@NotNull HttpClient client, @NotNull URI uri, @NotNull String witness) {
        try {
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri).build(), BodyHandlers.ofString());

            if (response.statusCode() == 404) {
                return Optional.empty();
            } else if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Recieved status code {} for URI {}", response.statusCode(), uri);
            }

            return Optional.of(response.body().equals(witness));
        } catch (IOException | InterruptedException e) {
            LoggerFactory.getLogger(FontCutter.class).error("IO exception whilst performing HTTP requests", e);
            return Optional.empty();
        }
    }

    public static boolean satisfiesHashes(@NotNull HttpClient client, @NotNull URI remoteURI, @NotNull GAVCE gavce, @NotNull DigestValues digests) {
        // md5, sha1, sha256, sha512
        URI parentPath = remoteURI.resolve(gavce.group().replace('.', '/')).resolve(gavce.artifactId()).resolve(gavce.version());

        String baseName = gavce.artifactId();
        if (gavce.classifier() != null) {
            baseName += "-" + gavce.classifier();
        }
        baseName += "." + gavce.extension();

        Optional<Boolean> md5 = FontCutter.satisfiesHash(client, parentPath.resolve(baseName + ".md5"), digests.md5Hash());
        Optional<Boolean> sha1 = FontCutter.satisfiesHash(client, parentPath.resolve(baseName + ".sha1"), digests.sha1Hash());
        Optional<Boolean> sha256 = FontCutter.satisfiesHash(client, parentPath.resolve(baseName + ".sha256"), digests.sha256Hash());
        Optional<Boolean> sha512 = FontCutter.satisfiesHash(client, parentPath.resolve(baseName + ".sha512"), digests.sha512Hash());

        boolean allEmpty = md5.isEmpty() && sha1.isEmpty() && sha256.isEmpty() && sha512.isEmpty();

        return !allEmpty && md5.orElse(Boolean.TRUE) && sha1.orElse(Boolean.TRUE) && sha256.orElse(Boolean.TRUE) && sha512.orElse(Boolean.TRUE);
    }

    @NotNull
    private static String toHex(byte @NotNull[] array) {
        char[] cstr = new char[array.length * 2];

        for (int i = array.length, j = i * 2; --i >= 0;) {
            cstr[--j] = FontCutter.CHAR_LOOKUP[array[i] & 0x0F];
            cstr[--j] = FontCutter.CHAR_LOOKUP[(array[i] >>> 4) & 0x0F];
        }

        return new String(cstr);
    }

    private static void upload(@NotNull HttpClient client, @NotNull URI parentPath, @NotNull String baseName, @NotNull DigestValues digests, BodyPublisher mainPublisher) {
        try {
            HttpResponse<Void> response = client.send(HttpRequest.newBuilder(parentPath.resolve(baseName)).PUT(mainPublisher).build(), BodyHandlers.discarding());
            if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Response code is {} for deployed URI {}", response.statusCode(), response.request().uri());
            } else {
                LoggerFactory.getLogger(FontCutter.class).info("Uploaded contents to {}", response.request().uri());
            }
            response = client.send(HttpRequest.newBuilder(parentPath.resolve(baseName + ".md5")).PUT(BodyPublishers.ofString(digests.md5Hash(), StandardCharsets.UTF_8)).build(), BodyHandlers.discarding());
            if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Response code is {} for deployed csum URI {}", response.statusCode(), response.request().uri());
            } else {
                LoggerFactory.getLogger(FontCutter.class).info("Uploaded checksum to {}", response.request().uri());
            }
            response = client.send(HttpRequest.newBuilder(parentPath.resolve(baseName + ".sha1")).PUT(BodyPublishers.ofString(digests.sha1Hash(), StandardCharsets.UTF_8)).build(), BodyHandlers.discarding());
            if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Response code is {} for deployed csum URI {}", response.statusCode(), response.request().uri());
            } else {
                LoggerFactory.getLogger(FontCutter.class).info("Uploaded checksum to {}", response.request().uri());
            }
            response = client.send(HttpRequest.newBuilder(parentPath.resolve(baseName + ".sha256")).PUT(BodyPublishers.ofString(digests.sha256Hash(), StandardCharsets.UTF_8)).build(), BodyHandlers.discarding());
            if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Response code is {} for deployed csum URI {}", response.statusCode(), response.request().uri());
            } else {
                LoggerFactory.getLogger(FontCutter.class).info("Uploaded checksum to {}", response.request().uri());
            }
            response = client.send(HttpRequest.newBuilder(parentPath.resolve(baseName + ".sha512")).PUT(BodyPublishers.ofString(digests.sha512Hash(), StandardCharsets.UTF_8)).build(), BodyHandlers.discarding());
            if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Response code is {} for deployed csum URI {}", response.statusCode(), response.request().uri());
            } else {
                LoggerFactory.getLogger(FontCutter.class).info("Uploaded checksum to {}", response.request().uri());
            }
        } catch (IOException | InterruptedException e1) {
            LoggerFactory.getLogger(FontCutter.class).error("Unable to upload files for base name '" + baseName + "' in base URI " + parentPath, e1);
            throw new AssertionError(e1);
        }
    }
}
