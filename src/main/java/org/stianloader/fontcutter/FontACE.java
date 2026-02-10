package org.stianloader.fontcutter;

import org.jetbrains.annotations.NotNull;

public record FontACE(@NotNull String artifactId, @NotNull String classifier, @NotNull String extension) implements Comparable<FontACE> {

    @Override
    public int compareTo(FontACE o) {
        int cmp = this.artifactId.compareTo(o.artifactId);

        if (cmp == 0 && (cmp = this.classifier.compareTo(o.classifier)) == 0) {
            return this.extension.compareTo(o.extension);
        }

        return cmp;
    }
}
