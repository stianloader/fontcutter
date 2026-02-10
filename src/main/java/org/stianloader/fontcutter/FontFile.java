package org.stianloader.fontcutter;

import java.nio.file.Path;
import java.util.Locale;

import org.jetbrains.annotations.NotNull;

public record FontFile(@NotNull String fontName, @NotNull String classifier, @NotNull String extension, @NotNull Path path) {
    @NotNull
    public FontACE getACE() {
        return new FontACE(this.fontName.toLowerCase(Locale.ROOT), this.classifier, this.extension);
    }
}
