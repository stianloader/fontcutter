package org.stianloader.fontcutter;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
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
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stianloader.fontcutter.Publishable.BytePublishable;
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

    private static void deploy(@NotNull HttpClient client, @NotNull URI remoteURI, Map<GAVCE, Map.Entry<Publishable, DigestValues>> deploymentFiles) {
        record GA(@NotNull String group, @NotNull String artifactId) { }

        Map<GA, String> deployedGAs = new LinkedHashMap<>();

        for (Map.Entry<GAVCE, Map.Entry<Publishable, DigestValues>> e : deploymentFiles.entrySet()) {
            GAVCE gavce = e.getKey();

            URI parentPath = remoteURI.resolve(gavce.group().replace('.', '/') + "/" + gavce.artifactId() + "/" + gavce.version() + "/");

            String baseName = gavce.artifactId() + "-" + gavce.version();
            if (gavce.classifier() != null) {
                baseName += "-" + gavce.classifier();
            }
            baseName += "." + gavce.extension();

            DigestValues digests = Objects.requireNonNull(e.getValue().getValue());
            FontCutter.upload(client, parentPath, baseName, digests, e.getValue().getKey().getPublisher());

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

            DigestValues metadataDigests = FontCutter.loadHashes(uploadData);

            FontCutter.upload(client, resolvedURIparent, "maven-metadata.xml", metadataDigests, BodyPublishers.ofByteArray(uploadData));
        }
    }

    private static void deploy(@NotNull Map<FontACE, FontFile> licenseFiles, @NotNull FontACE ace, @NotNull String groupId,
            @NotNull String version, @NotNull Map<GAVCE, Map.Entry<Publishable, DigestValues>> deploymentFiles,
            @NotNull String projectURL, @NotNull HttpClient client, @NotNull URI remoteURI) {
        // Add license file to files to deploy
        FontFile licenseFile = licenseFiles.get(ace);
        GAVCE licenseGAVCE = new GAVCE(groupId, ace.artifactId(), version, "license", licenseFile.extension());
        GAVCE pomGAVCE = new GAVCE(groupId, ace.artifactId(), version, null, "pom");
        GAVCE jarGAVCE = new GAVCE(groupId, ace.artifactId(), version, null, "jar");

        List<FontFile> jarElements = deploymentFiles.values()
                .stream()
                .map(Map.Entry::getKey)
                .filter(x -> x instanceof FontFile)
                .map(x -> (FontFile) x)
                .toList();

        Map.Entry<@NotNull Publishable, DigestValues> pomEntry = FontCutter.genPOM(groupId, ace.artifactId(), version, projectURL, licenseFile);
        Map.Entry<Publishable, DigestValues> jarEntry = FontCutter.genJAR(jarElements, groupId, ace.artifactId(), version, licenseFile.path(), pomEntry.getKey());

        deploymentFiles.put(pomGAVCE, pomEntry);
        deploymentFiles.put(jarGAVCE, jarEntry);
        deploymentFiles.put(licenseGAVCE, Map.entry(licenseFile, FontCutter.loadHashes(licenseFile.path())));

        FontCutter.deploy(Objects.requireNonNull(client), remoteURI, deploymentFiles);
    }

    @NotNull
    private static Map.Entry<Publishable, DigestValues> genJAR(@NotNull Iterable<FontFile> deploymentFiles, @NotNull String groupId, @NotNull String artifactId, @NotNull String version, @NotNull Path licenseFile, @NotNull Publishable pomFile) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zipOut = new ZipOutputStream(baos, StandardCharsets.UTF_8)) {
            zipOut.setLevel(9);

            zipOut.putNextEntry(new ZipEntry("/META-INF/"));
            zipOut.putNextEntry(new ZipEntry("/META-INF/LICENSES/"));
            zipOut.putNextEntry(new ZipEntry("/META-INF/LICENSES/" + artifactId + "/"));
            zipOut.putNextEntry(new ZipEntry("/META-INF/LICENSES/" + artifactId + "/LICENSE"));
            try (InputStream rawIn = Files.newInputStream(licenseFile)) {
                rawIn.transferTo(zipOut);
            }
            zipOut.closeEntry();

            zipOut.putNextEntry(new ZipEntry("/META-INF/maven/"));
            zipOut.putNextEntry(new ZipEntry("/META-INF/maven/" + groupId + "/"));
            zipOut.putNextEntry(new ZipEntry("/META-INF/maven/" + groupId + "/" + artifactId + "/"));

            {
                zipOut.putNextEntry(new ZipEntry("/META-INF/maven/" + groupId + "/" + artifactId + "/pom.properties"));
                // Using Properties violates reproducible builds but I also don't want to mess up random stuff like Unicode escaping,
                // so yeah. Reproducible build verification should probably ignore file metadata anyways
                Properties pomProperties = new Properties();
                pomProperties.put("artifactId", artifactId);
                pomProperties.put("groupId", groupId);
                pomProperties.put("version", version);

                pomProperties.store(zipOut, null);
                zipOut.closeEntry();
            }

            {
                zipOut.putNextEntry(new ZipEntry("/META-INF/maven/" + groupId + "/" + artifactId + "/pom.xml"));
                pomFile.asInputStream().transferTo(zipOut);
                zipOut.closeEntry();
            }

            for (FontFile file : deploymentFiles) {
                String nameSpec = "/" + file.fontName().toLowerCase(Locale.ROOT) + "-" + file.classifier() + "." + file.extension();
                zipOut.putNextEntry(new ZipEntry(nameSpec));
                try (InputStream rawIn = Files.newInputStream(file.path())) {
                    rawIn.transferTo(zipOut);
                }
                zipOut.closeEntry();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        byte[] rawData = baos.toByteArray();
        return Map.entry(new BytePublishable(rawData), FontCutter.loadHashes(rawData));
    }

    @NotNull
    private static Map.Entry<@NotNull Publishable, DigestValues> genPOM(@NotNull String groupId, @NotNull String artifactId, @NotNull String version, @NotNull String pomURL, @NotNull FontFile licenseFile) {
        Map<String, String> rootAttributes = new HashMap<>();
        rootAttributes.put("xsi:schemaLocation", "http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd");
        XmlElement pomRoot = new XmlElement(null, "project", rootAttributes);
        {
            XmlElement modelVersion = new XmlElement(pomRoot, "modelVersion", new HashMap<>());
            modelVersion.setText("4.0.0");
            pomRoot.appendChild(modelVersion);
        }
        {
            XmlElement groupIdXml = new XmlElement(pomRoot, "groupId", new HashMap<>());
            groupIdXml.setText(groupId);
            pomRoot.appendChild(groupIdXml);
        }
        {
            XmlElement artifactIdXml = new XmlElement(pomRoot, "artifactId", new HashMap<>());
            artifactIdXml.setText(artifactId);
            pomRoot.appendChild(artifactIdXml);
        }
        {
            XmlElement versionXml = new XmlElement(pomRoot, "version", new HashMap<>());
            versionXml.setText(version);
            pomRoot.appendChild(versionXml);
        }
        {
            XmlElement name = new XmlElement(pomRoot, "name", new HashMap<>());
            name.setText(artifactId);
            pomRoot.appendChild(name);
        }
        {
            XmlElement description = new XmlElement(pomRoot, "description", new HashMap<>());
            description.setText("Artifact generated by FontCutter, Data generated sourced from Tommyettinger's Fontwriter");
            pomRoot.appendChild(description);
        }
        {
            XmlElement url = new XmlElement(pomRoot, "url", new HashMap<>());
            url.setText(pomURL);
            pomRoot.appendChild(url);
        }
        {
            XmlElement packaging = new XmlElement(pomRoot, "packaging", new HashMap<>());
            packaging.setText("jar");
            pomRoot.appendChild(packaging);
        }
        {
            // Try to automatically detect license
            String licenseName = null;
            String licenseURL = null;

            try {
                String licenseContent = Files.readString(licenseFile.path(), StandardCharsets.UTF_8);

                if (licenseContent.contains("http://creativecommons.org/licenses/by-sa/3.0/")
                        || licenseContent.contains("https://creativecommons.org/licenses/by-sa/3.0/")) {
                    licenseName = "CC-BY-SA-3.0";
                    licenseURL = "https://spdx.org/licenses/CC-BY-SA-3.0.html";
                }

                if (licenseContent.contains("SIL OPEN FONT LICENSE Version 1.1")
                        || (licenseContent.contains("SIL Open Font License") && licenseContent.contains("Version 1.1 - 26 February 2007"))) {
                    if (licenseName != null) {
                        throw new IllegalStateException("Duplicate licenses detected for " + licenseFile.path());
                    }
                    if (licenseContent.contains("with Reserved Font Name")) {
                        licenseName = "OFL-1.1-RFN";
                        licenseURL = "https://spdx.org/licenses/OFL-1.1-RFN.html";
                    } else {
                        licenseName = "OFL-1.1-no-RFN";
                        licenseURL = "https://spdx.org/licenses/OFL-1.1-no-RFN.html";
                    }
                }

                if (licenseContent.contains("https://creativecommons.org/publicdomain/zero/1.0/")
                        || licenseContent.contains("CC0 1.0 Universal")) {
                    if (licenseName != null) {
                        throw new IllegalStateException("Duplicate licenses detected for " + licenseFile.path());
                    }

                    licenseName = "CC0-1.0";
                    licenseURL = "https://spdx.org/licenses/CC0-1.0.html";
                }

                if (licenseContent.contains("MIT License")) {
                    if (licenseName != null) {
                        throw new IllegalStateException("Duplicate licenses detected for " + licenseFile.path());
                    }

                    licenseName = "MIT";
                    licenseURL = "https://spdx.org/licenses/MIT.html";
                }

                if (licenseContent.contains("Creative Commons Attribution-ShareAlike 4.0 International Public")) {
                    if (licenseName != null) {
                        throw new IllegalStateException("Duplicate licenses detected for " + licenseFile.path());
                    }

                    licenseName = "CC-BY-SA-4.0";
                    licenseURL = "https://spdx.org/licenses/CC-BY-SA-4.0.html";
                }

                if (licenseContent.contains("http://creativecommons.org/licenses/by-nd/3.0/")) {
                    if (licenseName != null) {
                        throw new IllegalStateException("Duplicate licenses detected for " + licenseFile.path());
                    }

                    licenseName = "CC-BY-ND-3.0";
                    licenseURL = "https://spdx.org/licenses/CC-BY-ND-3.0.html";
                }

                if (licenseContent.contains("Apache License") && licenseContent.contains("Version 2.0, January 2004")) {
                    if (licenseName != null) {
                        throw new IllegalStateException("Duplicate licenses detected for " + licenseFile.path());
                    }

                    licenseName = "Apache-2.0";
                    licenseURL = "https://spdx.org/licenses/Apache-2.0.html";
                }
            } catch (IOException e) {
                throw new UncheckedIOException("Cannot read license file", e);
            }

            XmlElement licenses = new XmlElement(pomRoot, "licenses", new HashMap<>());
            pomRoot.appendChild(licenses);
            XmlElement license = new XmlElement(licenses, "license", new HashMap<>());
            licenses.appendChild(license);
            {
                XmlElement comment = new XmlElement(license, "comment", new HashMap<>());
                comment.setText("Provided automatically detected license name and URL may be inaccurate; See attached license file in JAR bundle or distributed license file within the repository for the actual license.");
                license.appendChild(comment);
            }
            {
                XmlElement distribution = new XmlElement(license, "distribution", new HashMap<>());
                distribution.setText("repo");
                license.appendChild(distribution);
            }
            if (licenseName != null) {
                XmlElement name = new XmlElement(license, "name", new HashMap<>());
                name.setText(licenseName);
                license.appendChild(name);
            }
            if (licenseURL != null) {
                XmlElement url = new XmlElement(license, "url", new HashMap<>());
                url.setText(licenseURL);
                license.appendChild(url);
            }
        }

        XmlParser parser = XmlParser.newXmlParser().escapeXml().charset(StandardCharsets.UTF_8).shouldPrettyPrint().build();
        final byte @NotNull[] pomData = parser.domToXml(pomRoot).getBytes(StandardCharsets.UTF_8);

        return Map.entry(new BytePublishable(pomData), FontCutter.loadHashes(pomData));
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
        String projectURL;

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

            OptionSpec<@NotNull String> projectURLSpec = parser.accepts("projectURL", "Project URL to use in POM files")
                    .withRequiredArg()
                    .defaultsTo("https://github.com/stianloader/fontcutter")
                    .ofType(String.class);

            OptionSet options = parser.parse(args);

            remoteURI = options.valueOf(remoteURISpec);
            repositoryPath = options.valueOf(repositoryPathSpec);
            groupId = options.valueOf(groupIdSpec);
            projectURL = options.valueOf(projectURLSpec);
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
                .filter(f -> !f.fontName().contains("Kingthings")) // License file not exactly correct
                .filter(f -> !f.fontName().contains("Yataghan")) // License file not exactly correct
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
            logger.error("File {} with coordinates {} has no license file attached", ace, file);
            throw new AssertionError();
        });

        AtomicReference<String> deploymentArtifactId = new AtomicReference<>("");
        Map<GAVCE, Map.Entry<Publishable, DigestValues>> deploymentFiles = new HashMap<>();
        AtomicBoolean requireDeployment = new AtomicBoolean();
        AtomicReference<@Nullable String> latestVersion = new AtomicReference<>(null);
        AtomicReference<@Nullable FontACE> lastACE = new AtomicReference<>(null);

        HttpClient client = Objects.requireNonNull(HttpClient.newHttpClient());

        deployableFiles.forEach((ace, fontFile) -> {
            DigestValues digest = FontCutter.loadHashes(fontFile.path());
            GAVCE baseGAVCE = new GAVCE(groupId, ace.artifactId(), version, ace.classifier(), ace.extension());

            if (!ace.artifactId().equals(deploymentArtifactId.getPlain())) {
                if (requireDeployment.getPlain()) {
                    FontCutter.deploy(licenseFiles, ace, groupId, version, deploymentFiles, projectURL, client, remoteURI);
                }
                deploymentFiles.clear();
                deploymentArtifactId.setPlain(ace.artifactId());
                requireDeployment.setPlain(false);
                MavenVersion remoteLatestVersion = FontCutter.getLatestVersion(client, remoteURI, baseGAVCE);
                latestVersion.setPlain(remoteLatestVersion == null ? null : remoteLatestVersion.getOriginText());
            }

            deploymentFiles.put(baseGAVCE, Map.entry(fontFile, digest));
            String remoteVersion = latestVersion.getPlain();

            if (remoteVersion != null) {
                GAVCE latestGAVCE = new GAVCE(groupId, ace.artifactId(), remoteVersion, ace.classifier(), ace.extension());

                if (!requireDeployment.getPlain() && !FontCutter.satisfiesHashes(client, remoteURI, latestGAVCE, digest)) {
                    LoggerFactory.getLogger(FontCutter.class).info("{} does not satisfy checksums; redeploying artifact as {}", latestGAVCE, baseGAVCE);
                    requireDeployment.setPlain(true);
                }
            } else {
                requireDeployment.setPlain(true);
            }

            lastACE.setPlain(ace);
        });

        if (requireDeployment.getPlain()) {
            FontACE ace = lastACE.getPlain();

            if (ace == null) {
                throw new AssertionError("ace == null");
            }

            FontCutter.deploy(licenseFiles, ace, groupId, version, deploymentFiles, projectURL, client, remoteURI);
        }

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
        URI parentPath = remoteURI.resolve(gavce.group().replace('.', '/') + "/" + gavce.artifactId() + "/" + gavce.version() + "/");

        String baseName = gavce.artifactId() + "-" + gavce.version();
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
                LoggerFactory.getLogger(FontCutter.class).debug("Uploaded checksum to {}", response.request().uri());
            }
            response = client.send(HttpRequest.newBuilder(parentPath.resolve(baseName + ".sha1")).PUT(BodyPublishers.ofString(digests.sha1Hash(), StandardCharsets.UTF_8)).build(), BodyHandlers.discarding());
            if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Response code is {} for deployed csum URI {}", response.statusCode(), response.request().uri());
            } else {
                LoggerFactory.getLogger(FontCutter.class).debug("Uploaded checksum to {}", response.request().uri());
            }
            response = client.send(HttpRequest.newBuilder(parentPath.resolve(baseName + ".sha256")).PUT(BodyPublishers.ofString(digests.sha256Hash(), StandardCharsets.UTF_8)).build(), BodyHandlers.discarding());
            if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Response code is {} for deployed csum URI {}", response.statusCode(), response.request().uri());
            } else {
                LoggerFactory.getLogger(FontCutter.class).debug("Uploaded checksum to {}", response.request().uri());
            }
            response = client.send(HttpRequest.newBuilder(parentPath.resolve(baseName + ".sha512")).PUT(BodyPublishers.ofString(digests.sha512Hash(), StandardCharsets.UTF_8)).build(), BodyHandlers.discarding());
            if (response.statusCode() != 200) {
                LoggerFactory.getLogger(FontCutter.class).warn("Response code is {} for deployed csum URI {}", response.statusCode(), response.request().uri());
            } else {
                LoggerFactory.getLogger(FontCutter.class).debug("Uploaded checksum to {}", response.request().uri());
            }
        } catch (IOException | InterruptedException e1) {
            LoggerFactory.getLogger(FontCutter.class).error("Unable to upload files for base name '" + baseName + "' in base URI " + parentPath, e1);
            throw new AssertionError(e1);
        }
    }
}
