package org.stianloader.fontcutter;

import java.util.Objects;

import org.jetbrains.annotations.NotNull;

import joptsimple.ValueConverter;

public final class NotNullStringConverter implements ValueConverter<@NotNull String> {
    @Override
    @NotNull
    public String convert(String value) {
        return Objects.requireNonNull(value);
    }

    @Override
    @NotNull
    public Class<@NotNull String> valueType() {
        return String.class;
    }

    @Override
    public String valuePattern() {
        return null;
    }
}
