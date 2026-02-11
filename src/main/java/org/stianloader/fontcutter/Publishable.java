package org.stianloader.fontcutter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;

import org.jetbrains.annotations.NotNull;

public interface Publishable {

    public static final class BytePublishable implements Publishable {
        private byte @NotNull[] data;

        public BytePublishable(byte @NotNull[] data) {
            this.data = data;
        }

        @Override
        @NotNull
        public InputStream asInputStream() throws IOException {
            return new ByteArrayInputStream(this.data);
        }

        @Override
        @NotNull
        public BodyPublisher getPublisher() {
            return BodyPublishers.ofByteArray(this.data);
        }
    }

    @NotNull
    public BodyPublisher getPublisher();

    @NotNull
    public InputStream asInputStream() throws IOException;
}
