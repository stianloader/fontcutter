package org.stianloader.fontcutter;

import org.jetbrains.annotations.NotNull;

public record DigestValues(@NotNull String md5Hash, @NotNull String sha1Hash, @NotNull String sha256Hash, @NotNull String sha512Hash) {

}
