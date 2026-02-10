package org.stianloader.fontcutter;

import java.net.URI;
import java.util.Objects;

import org.jetbrains.annotations.NotNull;

import joptsimple.ValueConverter;

public class URIDirectoryConverter implements ValueConverter<@NotNull URI> {

    public static final URIDirectoryConverter INSTANCE = new URIDirectoryConverter();

    private URIDirectoryConverter() {
        // Nothing to do
    }

    @Override
    @NotNull
    public URI convert(String value) {
        return URI.create(Objects.requireNonNull(value, "'value' may not be null!").endsWith("/") ? value : value + "/");
    }

    @Override
    @NotNull
    public Class<@NotNull URI> valueType() {
        return URI.class;
    }

    @Override
    public String valuePattern() {
        return null;
    }
}
