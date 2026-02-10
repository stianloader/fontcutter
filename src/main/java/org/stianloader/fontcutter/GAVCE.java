package org.stianloader.fontcutter;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public record GAVCE(@NotNull String group, @NotNull String artifactId, @NotNull String version, @Nullable String classifier, String extension) {

}
