package org.stianloader.fontcutter;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

import org.jetbrains.annotations.NotNull;

public record FontFile(@NotNull String fontName, @NotNull String classifier, @NotNull String extension, @NotNull Path path) implements Publishable {
    @NotNull
    public FontACE getACE() {
        return new FontACE(this.fontName.toLowerCase(Locale.ROOT), this.classifier, this.extension);
    }

    @Override
    @NotNull
    public BodyPublisher getPublisher() {
        try {
            return BodyPublishers.ofFile(this.path());
        } catch (FileNotFoundException e) {
            throw new IllegalStateException("File " + this.path() + " does not exist!");
        }
    }

    @Override
    @NotNull
    public InputStream asInputStream() throws IOException {
        return Files.newInputStream(this.path());
    }
}
